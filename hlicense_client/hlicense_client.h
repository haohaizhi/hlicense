#ifndef HLICENSE_CLIENT_H
#define HLICENSE_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 默认路径 */
#define DEVICE_SN_FILE "/etc/license/device.did"
#define RSA_PUBKEY_FILE "/etc/license/public_key.pem"

#define INTERFACE_NAME "eno1"




int validate_license();     //0 true   1 false
int import_license(const char *license_file);    //0 true   1 false


#endif
