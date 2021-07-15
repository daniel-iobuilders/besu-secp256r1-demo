/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package org.hyperledger.besu.secp256r1.demo;

import org.hyperledger.besu.secp256r1.demo.Web3jNist.NistCredentials;
import org.hyperledger.besu.secp256r1.demo.Web3jNist.NistTransactionManager;
import org.hyperledger.besu.secp256r1.demo.contract.DemoErc20;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;

import java.io.Console;
import java.math.BigInteger;

public class App {
    public static void main(String[] args) throws Exception {
        // address 1e842ba1c6ec125a6f010a161193c084502a8887
        NistCredentials owner = NistCredentials.create("b0b7ab78f5d723651981c490777fe1adf9e8e6de3583c824af3dbfb6edb27fc9");

        // address 232fc3893c092b74061caa8819f3ba0ac1d24682
        NistCredentials userA = NistCredentials.create("964471f8216a087ceb85670d1bed9923841f095599f3883cc74d6efce7c64604");

        System.out.println("Owner address: " + owner.getAddress());
        System.out.println("UserA address: " + userA.getAddress());
        String userB = "1b54F0707a12ec6c8a17CdFb2C9c69bBB6Fe98b9";
        System.out.println("UserB address: 0x" + userB);

        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8545"));
        NistTransactionManager transactionManagerOwner = new NistTransactionManager(web3j, owner, 2018);

        waitForInput("Deploy ERC20 contract.", "Deploying...");
        DemoErc20 tokenOwner = DemoErc20.deploy(web3j, transactionManagerOwner, new DefaultGasProvider()).send();

        System.out.println("Contract deployed at " +  tokenOwner.getContractAddress());
        System.out.println("Contract deployed tx id " +  tokenOwner.getTransactionReceipt().get().getTransactionHash());
        System.out.println("Owner has 10.000 tokens");

        BigInteger decimals = tokenOwner.decimals().send();
        BigInteger multiplier = BigInteger.valueOf(10).pow(decimals.intValue());

        waitForInput("Owner transfers 1.000 tokens to UserA.", "Transferring...");
        BigInteger transferAmountUserA = BigInteger.valueOf(1000).multiply(multiplier);
        TransactionReceipt receiptTransferUserA = tokenOwner.transfer(userA.getAddress(), transferAmountUserA).send();
        System.out.println("Transfer successful: " + receiptTransferUserA.getTransactionHash());

        NistTransactionManager transactionManagerUserA = new NistTransactionManager(web3j, userA, 2018);
        DemoErc20 tokenUserA = DemoErc20.load(tokenOwner.getContractAddress(), web3j, transactionManagerUserA, new DefaultGasProvider());

        waitForInput("UserA transfers 500 tokens to UserB", "Transferring...");
        BigInteger transferAmountUserB = BigInteger.valueOf(500).multiply(multiplier);
        TransactionReceipt receiptTransferUserB = tokenUserA.transfer(userB, transferAmountUserB).send();
        System.out.println("Transfer successful: " + receiptTransferUserB.getTransactionHash() + "\n");
    }

    private static void waitForInput(final String waitMessage, final String confirmationMessage) {
        final Console console = System.console();

        if (console == null) {
            return;
        }

        console.format("\n" + waitMessage + "\nPress ENTER to proceed.\n");
        console.readLine();
        console.format(confirmationMessage + "\n");

    }
}
