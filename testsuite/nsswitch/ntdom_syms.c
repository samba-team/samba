/*
 * Test required functions are exported from the ntdom.so library.
 */

#include <stdio.h>
#include <dlfcn.h>

/* Symbol list to check */

static char *symlist[] = {
    "_nss_ntdom_getgrent_r",
    "_nss_ntdom_endgrent",
    "_nss_ntdom_endpwent",
    "_nss_ntdom_getgrgid_r",
    "_nss_ntdom_getgrnam_r",
    "_nss_ntdom_getpwent_r",
    "_nss_ntdom_getpwnam_r",
    "_nss_ntdom_getpwuid_r",
    "_nss_ntdom_setgrent",
    "_nss_ntdom_setpwent",
    NULL
};

/* Main function */

int main(int argc, char **argv)
{
    void *handle, *sym;
    int i, y;

    /* Open library */

    if (argc != 2) {
        printf("FAIL: usage '%s sharedlibname'\n", argv[0]);
        return 1;
    }

    handle = dlopen(argv[1], RTLD_NOW);

    if (handle == NULL) {
        printf("FAIL: could not dlopen library: %s\n", dlerror());
        return 1;
    }

    /* Read symbols */

    for (i = 0; symlist[i] != NULL; i++) {
        sym = dlsym(handle, symlist[i]);
        if (sym == NULL) {
            printf("FAIL: could not resolve symbol '%s': %s\n",
                   symlist[i], dlerror());
            return 1;
        } else {
            printf("loaded symbol '%s' ok\n", symlist[i]);
        }
    }

    /* Clean up */

    dlclose(handle);
    return 0;
}
