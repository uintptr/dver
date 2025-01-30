# Directory Verification (`dver`)

Sign a directory to be deployed in a hostile environment and verify it's authenticity

```
product/
├── server.py
└── www
    ├── index.html
    └── js
        └── app.js
```

## Sign The Deployment Directory

```
Signing:
    Directory:          /tmp/product
    Private Key:        /home/joe/.ssh/id_ed25519
    Hash Type:          sha256
    Signature File:     /tmp/product/dver.sig
    Signature Type:     complete
    File Size:          1.48 KB
```

## Verify The Deployment Directory

```
Verifying:
    Directory:          /tmp/product
    Public Key:         /home/joe/.ssh/id_ed25519.pub
    Signature File:     /tmp/product/dver.sig
    Hash Type:          sha256
    Verification:       Success
```

## Change the directory

```
printf '#!/usr/bin/env python3\nprint("Hello, World!")\n' > /tmp/product/server.py
```

## Verify The Deployment Directory

```
Verifying:
    Directory:          /tmp/product
    Public Key:         /home/joe/.ssh/id_ed25519.pub
    Signature File:     /tmp/product/dver.sig
    Hash Type:          sha256
    Verification:       Failure
Error: VerificationFailure
```