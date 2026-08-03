/*
 * MicroLink over Ethernet (ESP32-P4) — minimal test for the #16 TLS control
 * plane. Brings up the P4's internal EMAC (RMII, external clock), waits for a
 * DHCP lease, then starts MicroLink with ctrl_tls=true so it can reach the
 * hosted Tailscale coordination server (controlplane.tailscale.com, HTTPS-only).
 *
 * The auth key and device name come from Kconfig (idf.py menuconfig ->
 * "MicroLink Configuration"): CONFIG_ML_TAILSCALE_AUTH_KEY, CONFIG_ML_DEVICE_NAME.
 *
 * Ethernet pin map is the Waveshare ESP32-P4 board (same as ESP-KVM).
 */
#include <string.h>

#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "soc/soc_caps.h"

#include "microlink.h"

static const char *TAG = "eth_ml";

/* Waveshare ESP32-P4 Ethernet (internal EMAC, RMII, clock fed in externally). */
#define ETH_PHY_ADDR 1
#define ETH_PHY_RST_GPIO 51
#define ETH_RMII_CLK_GPIO 50
#define ETH_RMII_TX_EN_GPIO 49
#define ETH_RMII_TXD0_GPIO 34
#define ETH_RMII_TXD1_GPIO 35
#define ETH_RMII_CRS_DV_GPIO 28
#define ETH_RMII_RXD0_GPIO 29
#define ETH_RMII_RXD1_GPIO 30
#define ETH_MDC_GPIO 31
#define ETH_MDIO_GPIO 52

static EventGroupHandle_t s_net_events;
#define NET_GOT_IP BIT0

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)id;
    ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
    ESP_LOGI(TAG, "Ethernet got IP: " IPSTR, IP2STR(&e->ip_info.ip));
    xEventGroupSetBits(s_net_events, NET_GOT_IP);
}

static void on_eth_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)data;
    if (id == ETHERNET_EVENT_CONNECTED) {
        ESP_LOGI(TAG, "Ethernet link up");
    } else if (id == ETHERNET_EVENT_DISCONNECTED) {
        ESP_LOGW(TAG, "Ethernet link down");
    }
}

static esp_err_t eth_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = ETH_PHY_ADDR;
    phy_config.reset_gpio_num = ETH_PHY_RST_GPIO;

    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_config.interface = EMAC_DATA_INTERFACE_RMII;
    emac_config.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    emac_config.clock_config.rmii.clock_gpio = ETH_RMII_CLK_GPIO;
#if SOC_EMAC_USE_MULTI_IO_MUX
    emac_config.emac_dataif_gpio.rmii.tx_en_num = ETH_RMII_TX_EN_GPIO;
    emac_config.emac_dataif_gpio.rmii.txd0_num = ETH_RMII_TXD0_GPIO;
    emac_config.emac_dataif_gpio.rmii.txd1_num = ETH_RMII_TXD1_GPIO;
    emac_config.emac_dataif_gpio.rmii.crs_dv_num = ETH_RMII_CRS_DV_GPIO;
    emac_config.emac_dataif_gpio.rmii.rxd0_num = ETH_RMII_RXD0_GPIO;
    emac_config.emac_dataif_gpio.rmii.rxd1_num = ETH_RMII_RXD1_GPIO;
#endif
    emac_config.smi_gpio.mdc_num = ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = ETH_MDIO_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_generic(&phy_config);
    if (!mac || !phy) {
        ESP_LOGE(TAG, "eth mac/phy alloc failed");
        return ESP_FAIL;
    }
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    ESP_ERROR_CHECK(
        esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_got_ip, NULL));
    ESP_ERROR_CHECK(
        esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, on_eth_event, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    return ESP_OK;
}

static void on_state_change(microlink_t *ml, microlink_state_t state, void *user)
{
    (void)ml;
    (void)user;
    ESP_LOGI(TAG, "MicroLink state -> %d%s", (int)state,
             state == ML_STATE_CONNECTED ? " (CONNECTED)" : "");
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    s_net_events = xEventGroupCreate();
    ESP_ERROR_CHECK(eth_start());

    ESP_LOGI(TAG, "Waiting for an Ethernet IP...");
    xEventGroupWaitBits(s_net_events, NET_GOT_IP, pdFALSE, pdTRUE, portMAX_DELAY);

    microlink_config_t config = {
        .auth_key = CONFIG_ML_TAILSCALE_AUTH_KEY,
        .device_name = CONFIG_ML_DEVICE_NAME,
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = 16,
        /* #16: the hosted Tailscale control plane is HTTPS-only, so wrap the
         * coordination connection in TLS. */
        .ctrl_tls = true,
    };

    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "microlink_init failed (auth key set?)");
        return;
    }
    microlink_set_state_callback(ml, on_state_change, NULL);

    ESP_LOGI(TAG, "Starting MicroLink over Ethernet (ctrl_tls=on)...");
    ESP_ERROR_CHECK(microlink_start(ml));

    while (!microlink_is_connected(ml)) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    ESP_LOGI(TAG, "CONNECTED — tailnet IP: %u.%u.%u.%u",
             (unsigned)(microlink_get_vpn_ip(ml) >> 24) & 0xFF,
             (unsigned)(microlink_get_vpn_ip(ml) >> 16) & 0xFF,
             (unsigned)(microlink_get_vpn_ip(ml) >> 8) & 0xFF,
             (unsigned)microlink_get_vpn_ip(ml) & 0xFF);
}
