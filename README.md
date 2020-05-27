# Secure File-Transfer-Protocol

A simple application developed in C with the OpenSSL library that allows for a secure transfer of large files (up to 4GiB) between a client and a server. For more details, see the documentation.

### Note ###
The provided certificates in the /certif folder are expired. To test the application generate new valid certificates with SimpleAuthority with the same name (i.e. gerardo_cert.pem).

### How to use ###
Navigate to the /src folder and open a terminal:
```shell
make
```
This will start a server terminal. Now open another terminal and launch the client:
```shell
./client
```

### Credits ###
This program was developed by R. Polini, D. Comola and G. Alvaro as part of the Foundations of Cybersecurity course for the MsC in Computer Engineering @ Univerisity of Pisa in 2019.
