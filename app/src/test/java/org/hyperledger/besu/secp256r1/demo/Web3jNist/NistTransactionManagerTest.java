package org.hyperledger.besu.secp256r1.demo.Web3jNist;

import org.junit.Before;
import org.junit.Test;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.protocol.Web3j;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class NistTransactionManagerTest {
    private NistTransactionManager transactionManager;
    private String deployContractCode = "60806040523480156200001157600080fd5b506040518060400160405280600c81526020016b22bc30b6b83632aa37b5b2b760a11b815250604051806040016040528060038152602001621151d560ea1b81525081600390805190602001906200006b929190620001ad565b50805162000081906004906020840190620001ad565b505050620000ba3362000099620000c060201b60201c565b620000a690600a620002b7565b620000b49061271062000385565b620000c5565b620003fa565b601290565b6001600160a01b038216620001205760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640160405180910390fd5b806002600082825462000134919062000253565b90915550506001600160a01b038216600090815260208190526040812080548392906200016390849062000253565b90915550506040518181526001600160a01b038316906000907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a35050565b828054620001bb90620003a7565b90600052602060002090601f016020900481019282620001df57600085556200022a565b82601f10620001fa57805160ff19168380011785";

    @Before
    public void setUp() {
        Credentials signer = Credentials.create(
                "1561d2a19b51f29ff4c0938d13ca44d44755022bc2ed66f4a5da0708bca12466",
                "95440b0e9cef3a697430f20e5ca66396996037c3acd8a69118357ed5e62ad1d5e262383eb9a28007a9d995510bd859e40e88c78e7f2233b7017b9e98e85a28bd");

        Web3j web3jMock = mock(Web3j.class);
        transactionManager = new NistTransactionManager(web3jMock, signer);
    }

    @Test
    public void signShouldBeSuccessfulIfNonceIsNotOne() {
        RawTransaction transaction1 = RawTransaction.createTransaction(
                BigInteger.ONE, BigInteger.valueOf(4100000000L), BigInteger.valueOf(9000000), null, deployContractCode);

        String signedTransaction1 = transactionManager.sign(transaction1);

        assertThat(signedTransaction1).isNotBlank();

        RawTransaction transaction2 = RawTransaction.createTransaction(
                BigInteger.TWO, BigInteger.valueOf(4100000000L), BigInteger.valueOf(9000000), null, deployContractCode);

        String signedTransaction2 = transactionManager.sign(transaction2);

        assertThat(signedTransaction2).isNotBlank();
    }
}