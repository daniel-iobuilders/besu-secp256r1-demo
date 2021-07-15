package org.hyperledger.besu.secp256r1.demo.Web3jNist;

import org.web3j.crypto.Keys;
import org.web3j.utils.Numeric;

public class NistCredentials {
    private final NistECKeyPair ecKeyPair;
    private final String address;

    private NistCredentials(NistECKeyPair ecKeyPair, String address) {
        this.ecKeyPair = ecKeyPair;
        this.address = address;
    }

    public NistECKeyPair getEcKeyPair() {
        return ecKeyPair;
    }

    public String getAddress() {
        return address;
    }

    public static NistCredentials create(NistECKeyPair ecKeyPair) {
        String address = Numeric.prependHexPrefix(Keys.getAddress(ecKeyPair));
        return new NistCredentials(ecKeyPair, address);
    }

    public static NistCredentials create(String privateKey, String publicKey) {
        return create(new NistECKeyPair(Numeric.toBigInt(privateKey), Numeric.toBigInt(publicKey)));
    }

    public static NistCredentials create(String privateKey) {
        return create(NistECKeyPair.create(Numeric.toBigInt(privateKey)));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        NistCredentials that = (NistCredentials) o;

        if (ecKeyPair != null ? !ecKeyPair.equals(that.ecKeyPair) : that.ecKeyPair != null) {
            return false;
        }

        return address != null ? address.equals(that.address) : that.address == null;
    }

    @Override
    public int hashCode() {
        int result = ecKeyPair != null ? ecKeyPair.hashCode() : 0;
        result = 31 * result + (address != null ? address.hashCode() : 0);
        return result;
    }
}
