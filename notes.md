## Learn "the Hans" checklist:

https://github.com/Cyfrin/audit-checklist/tree/main

how signing works:

1. take a private key + message (data, function selector, parameters)
2. smash it into Elliptic Curve Digital Signiture Algoritm
   1. this outputs v, r, and s
   2. we can use these values to verify someone's signiture using ecrecover

how verification works:

1.  Get the signed message 2. Break into v, r, s
2.  Get the data itself
3.  use it as input parameters for `ecrecover`
