# Third-party notices

This repository includes two third-party binaries, unmodified, because the project is built
against them. They are **not** covered by this repo's GPLv3 license (see `LICENSE`); each remains
under its own terms, listed below.

## BouncyCastle.Crypto.dll

- **What:** Bouncy Castle for .NET, version 1.7.4114.6375 (April 2011 build)
- **Copyright:** Copyright (c) 2000-2011 The Legion of the Bouncy Castle (https://www.bouncycastle.org)
  — as stated in the assembly's own metadata (`Company: The Legion of the Bouncy Castle`,
  `Copyright (C) 2000-2011`)
- **License:** MIT-style license (the 2011 releases describe it as an adaptation of the MIT / X11
  license). The text below is the MIT license as published by the project in its current
  [bc-csharp repository](https://github.com/bcgit/bc-csharp/blob/master/LICENSE.md); for the
  exact wording that shipped with a given release, see https://www.bouncycastle.org/about/license/.

```
Copyright (c) 2000-2011 The Legion of the Bouncy Castle (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: The above copyright notice and this
permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## ThoughtWorks.QRCode.dll

- **What:** ThoughtWorks.QRCode.NET component, version 1.0.2774.19990 (2007 build), used for the
  QR codes in printed paper wallets / coin inserts.
- **License: not determined.** The assembly carries no copyright or license metadata, no license
  file was shipped with the copy this project uses, and none could be found for it elsewhere (the
  NuGet package metadata and the public GitHub mirrors list no license). One secondary repost of
  a CodeProject article about the library mentions the CodeProject Open License (CPOL), but that
  is unverified and may refer only to the article.
- **Status:** it is included only because the upstream project requires it to build. If you are
  the rights holder, or know its license, please open an issue and this file will be updated —
  or the binary removed — accordingly.
