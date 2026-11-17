/*
 * MicroLink over Ethernet.
 *
 * Brings up one Ethernet interface (WT32-ETH01, a W5500 SPI module, or
 * QEMU's emulated MAC), waits for DHCP, then joins the tailnet. Nothing in
 * MicroLink is WiFi-specific: it uses lwIP sockets and advertises the
 * Ethernet address as its LAN endpoint.
 *
 * Needs ESP-IDF 5.x: ESP-IDF 6 moved the PHY, SPI-Ethernet and OpenCores
 * drivers into separate components.
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "microlink.h"

#if ESP_IDF_VERSION_MAJOR >= 6
#error "ethernet_connect needs ESP-IDF 5.x (ESP-IDF 6 moved the Ethernet PHY/MAC drivers to the component registry)"
#endif

static const char *TAG = "eth_main";
static EventGroupHandle_t s_events;
#define GOT_IP_BIT BIT0

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (id == ETHERNET_EVENT_CONNECTED) ESP_LOGI(TAG, "Ethernet link up");
    else if (id == ETHERNET_EVENT_DISCONNECTED) ESP_LOGW(TAG, "Ethernet link down");
}

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data) {
    const ip_event_got_ip_t *e = (const ip_event_got_ip_t *)data;
    ESP_LOGI(TAG, "Ethernet IP: " IPSTR, IP2STR(&e->ip_info.ip));
    xEventGroupSetBits(s_events, GOT_IP_BIT);
}

static void eth_start(void) {
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = NULL;
    esp_eth_phy_t *phy = NULL;

#if CONFIG_EXAMPLE_ETH_OPENETH
    phy_config.autonego_timeout_ms = 100;
    mac = esp_eth_mac_new_openeth(&mac_config);
    phy = esp_eth_phy_new_dp83848(&phy_config);
#elif CONFIG_EXAMPLE_ETH_WT32_ETH01
    /* GPIO16 powers the board's 50 MHz oscillator, which feeds the RMII
     * clock into GPIO0 (the EMAC default, EMAC_CLK_EXT_IN). */
    gpio_reset_pin(GPIO_NUM_16);
    gpio_set_direction(GPIO_NUM_16, GPIO_MODE_OUTPUT);
    gpio_set_level(GPIO_NUM_16, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    eth_esp32_emac_config_t emac = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac.smi_gpio.mdc_num = 23;
    emac.smi_gpio.mdio_num = 18;
    mac = esp_eth_mac_new_esp32(&emac, &mac_config);
    phy_config.phy_addr = 1;
    phy_config.reset_gpio_num = -1;
    phy = esp_eth_phy_new_lan87xx(&phy_config);
#elif CONFIG_EXAMPLE_ETH_W5500
    ESP_ERROR_CHECK(gpio_install_isr_service(0));
    spi_bus_config_t bus = {
        .sclk_io_num = CONFIG_EXAMPLE_W5500_SCLK,
        .mosi_io_num = CONFIG_EXAMPLE_W5500_MOSI,
        .miso_io_num = CONFIG_EXAMPLE_W5500_MISO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO));
    spi_device_interface_config_t dev = {
        .mode = 0,
        .clock_speed_hz = CONFIG_EXAMPLE_W5500_SPI_MHZ * 1000 * 1000,
        .spics_io_num = CONFIG_EXAMPLE_W5500_CS,
        .queue_size = 20,
    };
    eth_w5500_config_t w5500 = ETH_W5500_DEFAULT_CONFIG(SPI2_HOST, &dev);
    w5500.int_gpio_num = CONFIG_EXAMPLE_W5500_INT;
    if (w5500.int_gpio_num < 0) w5500.poll_period_ms = 10;
    mac = esp_eth_mac_new_w5500(&w5500, &mac_config);
    phy = esp_eth_phy_new_w5500(&phy_config);
#endif
    if (!mac || !phy) {
        ESP_LOGE(TAG, "Ethernet MAC/PHY driver could not be created");
        abort();
    }

    esp_eth_config_t cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&cfg, &eth));
#if CONFIG_EXAMPLE_ETH_W5500
    /* The W5500 has no MAC address of its own: use the chip's Ethernet MAC */
    uint8_t addr[6];
    ESP_ERROR_CHECK(esp_read_mac(addr, ESP_MAC_ETH));
    ESP_ERROR_CHECK(esp_eth_ioctl(eth, ETH_CMD_S_MAC_ADDR, addr));
#endif
    esp_netif_config_t ncfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *netif = esp_netif_new(&ncfg);
    ESP_ERROR_CHECK(esp_netif_attach(netif, esp_eth_new_netif_glue(eth)));
    ESP_ERROR_CHECK(esp_eth_start(eth));
}

static void on_state(microlink_t *ml, microlink_state_t state, void *arg) {
    if (state == ML_STATE_CONNECTED) {
        char ip[16];
        microlink_ip_to_str(microlink_get_vpn_ip(ml), ip);
        ESP_LOGI(TAG, "Connected! VPN IP: %s", ip);
    } else if (state == ML_STATE_NEEDS_LOGIN) {
        char url[MICROLINK_AUTH_URL_MAX];
        if (microlink_get_auth_url(ml, url, sizeof(url)) == ESP_OK) {
            printf("\nTo add this device to your tailnet, open:\n\n    %s\n\n", url);
        }
    } else if (state == ML_STATE_AUTH_FAILED) {
        ESP_LOGE(TAG, "Registration refused (auth key expired or used up?)");
    }
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_got_ip, NULL));

    eth_start();
    ESP_LOGI(TAG, "Waiting for an address (DHCP)...");
    xEventGroupWaitBits(s_events, GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    microlink_config_t config = {
        .auth_key = CONFIG_ML_TAILSCALE_AUTH_KEY,   /* "" = interactive login */
        .device_name = CONFIG_ML_DEVICE_NAME,
        .max_peers = CONFIG_ML_MAX_PEERS,
    };
    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "microlink_init failed");
        return;
    }
    microlink_set_state_callback(ml, on_state, NULL);
    ESP_ERROR_CHECK(microlink_start(ml));

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(30000));
        char ip[16];
        microlink_ip_to_str(microlink_get_vpn_ip(ml), ip);
        ESP_LOGI(TAG, "state=%d vpn=%s peers=%d free heap=%u", microlink_get_state(ml), ip,
                 microlink_get_peer_count(ml), (unsigned)esp_get_free_heap_size());
    }
}
