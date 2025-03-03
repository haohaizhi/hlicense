#ifndef HLICENSE_SERVER_H
#define HLICENSE_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 默认路径 */
#define RSA_PRIKEY_FILE "/etc/license/private_key.pem"


/*license 默认信息*/
/*
{
    "CustomerName":"",
    "AuthorName":"",
    "ProjectName":"",
    "LicenseId":"",
    "ESN":"",
    "CreateTime":"",
    "CurrentTime":"",
    "EndTime":"",
}
*/

#define CUSTOMER_NAME "iii-hong"
#define AUTHOR_NAME "hongqiang"
#define PROJECT_NAME "test"        //默认

#define DEFAULT_TIME 30        //默认30天授权



#endif