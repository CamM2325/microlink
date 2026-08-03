idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES microlink nvs_flash esp_eth esp_netif esp_event
)
