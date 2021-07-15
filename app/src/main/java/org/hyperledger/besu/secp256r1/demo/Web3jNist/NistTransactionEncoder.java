package org.hyperledger.besu.secp256r1.demo.Web3jNist;

import org.web3j.crypto.RawTransaction;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Bytes;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class NistTransactionEncoder {

    private static final int CHAIN_ID_INC = 35;
    private static final int LOWER_REAL_V = 27;

    public static byte[] signMessage(RawTransaction rawTransaction, NistCredentials credentials) {
        byte[] encodedTransaction = encode(rawTransaction);
        NistSign.SignatureData signatureData =
                NistSign.signMessage(encodedTransaction, credentials.getEcKeyPair());

        return encode(rawTransaction, signatureData);
    }

    public static byte[] signMessage(
            RawTransaction rawTransaction, long chainId, NistCredentials credentials) {
        byte[] encodedTransaction = encode(rawTransaction, chainId);
        NistSign.SignatureData signatureData =
                NistSign.signMessage(encodedTransaction, credentials.getEcKeyPair());

        NistSign.SignatureData eip155SignatureData = createEip155SignatureData(signatureData, chainId);
        return encode(rawTransaction, eip155SignatureData);
    }

    public static byte[] encode(RawTransaction rawTransaction) {
        return encode(rawTransaction, null);
    }

    public static byte[] encode(RawTransaction rawTransaction, long chainId) {
        NistSign.SignatureData signatureData =
                new NistSign.SignatureData(longToBytes(chainId), new byte[] {}, new byte[] {});
        return encode(rawTransaction, signatureData);
    }

    private static byte[] encode(RawTransaction rawTransaction, NistSign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(rawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    private static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public static List<RlpType> asRlpValues(
            RawTransaction rawTransaction, NistSign.SignatureData signatureData) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(rawTransaction.getNonce()));
        result.add(RlpString.create(rawTransaction.getGasPrice()));
        result.add(RlpString.create(rawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = rawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(rawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(rawTransaction.getData());
        result.add(RlpString.create(data));

        // add gas premium and fee cap if this is an EIP-1559 transaction
        if (rawTransaction.isEIP1559Transaction()) {
            result.add(RlpString.create(rawTransaction.getGasPremium()));
            result.add(RlpString.create(rawTransaction.getFeeCap()));
        }

        if (signatureData != null) {
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getV())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        return result;
    }

    public static NistSign.SignatureData createEip155SignatureData(
            NistSign.SignatureData signatureData, long chainId) {
        BigInteger v = Numeric.toBigInt(signatureData.getV());
        v = v.subtract(BigInteger.valueOf(LOWER_REAL_V));
        v = v.add(BigInteger.valueOf(chainId * 2));
        v = v.add(BigInteger.valueOf(CHAIN_ID_INC));

        return new NistSign.SignatureData(v.toByteArray(), signatureData.getR(), signatureData.getS());
    }
}
