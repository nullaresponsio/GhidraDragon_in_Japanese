--- softtpm.cpp
+++ softtpm.cpp
@@ -1,6 +1,8 @@
 #include "softtpm.hpp"
+#include <tbs.h>
+#pragma comment(lib, "tbs.lib")
 #include <openssl/rsa.h>
 #include <openssl/pem.h>
 #include <openssl/err.h>
@@ -128,6 +130,35 @@ std::vector<uint8_t> SoftTPM::ecdh(const std::vector<uint8_t>& peerDer){
     EC_KEY_free(peer);
     return secret;
 }
+
+// Windows TBS-based TPM command emulation
+void SoftTPM::openTbsContext() {
+    TBS_HCONTEXT ctx = 0;
+    TBS_CONTEXT_PARAMS params;
+    ZeroMemory(&params, sizeof(params));
+    params.version = TBS_CONTEXT_VERSION_ONE;
+    if (Tbsip_Context_Create(&params, &ctx) != TBS_SUCCESS) {
+        throw std::runtime_error("TBS context creation failed");
+    }
+    // store ctx in private member if needed
+}
+
+void SoftTPM::emulateTpmCommand(const std::vector<uint8_t>& cmd, std::vector<uint8_t>& resp) {
+    TBS_HCONTEXT ctx = /* previously opened */;
+    UINT32 status = 0, size = 0;
+    // first call to get size
+    Tbsip_Submit_Command(ctx, TBS_COMMAND_LOCALITY_ZERO, TBS_ORDINAL_NONE,
+                         cmd.data(), cmd.size(), nullptr, &size);
+    resp.resize(size);
+    status = Tbsip_Submit_Command(ctx, TBS_COMMAND_LOCALITY_ZERO, TBS_ORDINAL_NONE,
+                                  cmd.data(), cmd.size(), resp.data(), &size);
+    if (status != TBS_SUCCESS) {
+        throw std::runtime_error("TBS submit command failed");
+    }
+    resp.resize(size);
+}
