#ifndef _BASE64_H_
#define _BASE64_H_

int base64_encode(const void *data, int size, char **str);
int base64_decode(const char *str, void *data);

#endif
