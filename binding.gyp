{
    "targets": [
        {
            "target_name": "node_nl80211",
            "cflags!": [ "-fno-exceptions" ],
            "cflags_cc!": [ "-fno-exceptions" ],
            "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
            "sources": [
                "native_src/node_nl80211.cc"
            ],
            "include_dirs": [
                "<!@(node -p \"require('node-addon-api').include\")",
                "/usr/include/libnl3",
                "/usr/include"
                "native_src"
            ],
            "libraries": [
                "-lnl-3",
                "-lnl-genl-3",
                "-lwpa_client"
            ]
        }
    ]
}