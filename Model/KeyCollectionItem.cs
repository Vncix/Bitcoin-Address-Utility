// Copyright 2012 Mike Caldwell (Casascius)
// This file is part of Bitcoin Address Utility.

// Bitcoin Address Utility is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Bitcoin Address Utility is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Bitcoin Address Utility.  If not, see http://www.gnu.org/licenses/.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Casascius.Bitcoin {
    public class KeyCollectionItem {
        public KeyCollectionItem() { }

        public KeyCollectionItem(AddressBase address) {
            this.Address = address;
        }

        public KeyCollectionItem(EncryptedKeyPair ekp) {
            this.EncryptedKeyPair = ekp;
        }
        /// <summary>
        /// The encrypted item, if this item is encrypted.
        /// </summary>
        public EncryptedKeyPair EncryptedKeyPair;

        /// <summary>
        /// The plain item, if it is not encrypted.  This could be a PublicKey, KeyPair, etc.
        /// </summary>
        public AddressBase Address;

        /// <summary>
        /// The BIP38 passphrase, kept in plain text only if the user explicitly asked to retain
        /// it for export ("Keep passphrase for export" in the Generate Addresses window).
        /// Null otherwise.
        /// </summary>
        public string RetainedPassphrase;

        /// <summary>
        /// Gets the address in Base58, calculating it if necessary.
        /// </summary>
        public string GetAddressBase58() {
            if (Address != null) return Address.AddressBase58;
            return EncryptedKeyPair.GetAddress().AddressBase58;
        }

        /// <summary>
        /// Gets the private key in the best known printable form.
        /// </summary>
        public string PrivateKey {
            get {
                if (Address != null && Address is KeyPair) {
                    return ((KeyPair)Address).PrivateKey;
                } else if (EncryptedKeyPair != null) {
                    return EncryptedKeyPair.EncryptedPrivateKey;
                }
                return "Unknown";
            }
        }

        /// <summary>
        /// Describes the address format: "Compressed" or "Uncompressed" public key, or
        /// "Address only" when no public key is known. A non-zero address version byte
        /// (e.g. 111 testnet, 48 litecoin) is appended as ", ver N".
        /// </summary>
        public string AddressFormat {
            get {
                string kind;
                byte version = 0;
                if (Address != null) {
                    version = Address.AddressType;
                    kind = (Address is PublicKey)
                        ? (((PublicKey)Address).IsCompressedPoint ? "Compressed" : "Uncompressed")
                        : "Address only";
                } else if (EncryptedKeyPair != null) {
                    kind = EncryptedKeyPair.IsCompressedPoint ? "Compressed" : "Uncompressed";
                    if (EncryptedKeyPair.IsAddressAvailable()) version = EncryptedKeyPair.GetAddress().AddressType;
                } else {
                    return "Unknown";
                }
                return version == 0 ? kind : kind + ", ver " + version;
            }
        }

        /// <summary>
        /// Returns "MiniKey", "Known", "Encrypted", or "Unknown" depending on what private key we have.
        /// </summary>
        public string PrivateKeyKind {
            get {
                if (Address != null && Address is KeyPair) {
                    if (Address is MiniKeyPair) return "MiniKey";
                    return "Known";
                } else if (EncryptedKeyPair != null) {
                    return "Encrypted";
                }
                return "Unknown";
            }
        }

        public override string ToString() {
            if (Address != null) return Address.AddressBase58;
            if (EncryptedKeyPair == null) return "<null>";
            if (EncryptedKeyPair.IsAddressAvailable() == false) {
                return EncryptedKeyPair.EncryptedPrivateKey;
            }
            return EncryptedKeyPair.GetAddress().AddressBase58;
        }
    }
}
