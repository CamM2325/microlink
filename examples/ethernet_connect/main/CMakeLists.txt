idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES microlink nvs_flash esp_netif esp_event esp_eth esp_driver_gpio esp_driver_spi
)
