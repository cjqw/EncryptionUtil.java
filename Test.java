import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import message.*;

public class Test{
    public static void main(String[] args)throws Exception{
        // Initialize.
        String content = "test abcdefg GG orz mo mo mo   ";
        Message msg = new Message();
        KeyPair keys = msg.Generate();
        PrivateKey privateKey = keys.getPrivate();
        PublicKey publicKey = keys.getPublic();

        // Test encrypt.
        msg.Encrypt(content,publicKey);
        System.out.println(msg.Decrypt(privateKey));

        // Test signature.
        msg.Sign(privateKey);
        Boolean validate = msg.Validate(publicKey);
        System.out.println(validate);

        // Test toString.
        String st = msg.toString();

        // Test parsing.
        Message raw_msg = new Message(st);
        System.out.println(raw_msg.Decrypt(privateKey));
        System.out.println(raw_msg.Summary(privateKey));
    }
};
