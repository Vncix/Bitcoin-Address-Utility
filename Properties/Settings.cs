namespace BtcAddress.Properties {

    internal sealed partial class Settings {

        /// <summary>
        /// Whether newly generated random WIF keys use compressed public keys (default) or the
        /// older uncompressed form.  Mini keys and BIP38 keys always keep their original,
        /// uncompressed format, and deterministic keys are not affected (changing them would change
        /// the addresses they reproduce).
        /// </summary>
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("True")]
        public bool CompressedAddresses {
            get { return (bool)this["CompressedAddresses"]; }
            set { this["CompressedAddresses"] = value; }
        }
    }
}
