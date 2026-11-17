# The WireGuard sources in src/ are compiled by the microlink component
# (components/microlink/CMakeLists.txt), which makes MicroLink a single
# self-contained component. This stub only keeps projects building that still
# list components/microlink/components in EXTRA_COMPONENT_DIRS, as older
# instructions said: it adds the headers, no code (the symbols come from
# microlink, so nothing is linked twice).
idf_component_register(
    INCLUDE_DIRS
        "src"
        "src/crypto/refc"
)
