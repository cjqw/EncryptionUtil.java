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

        KeyPair mykeys = msg.Generate();
        PrivateKey myPrivateKey = mykeys.getPrivate();
        PublicKey myPublicKey = mykeys.getPublic();

        System.out.println("START");

        // Test encrypt.
        msg.Encrypt(666,content,myPrivateKey,publicKey);
        System.out.println(msg.Decrypt(privateKey));
        System.out.println(msg.getContent());

        // Test signature.
        Boolean validate = msg.Validate(myPublicKey);
        System.out.println(validate);

        // Test toString.
        String st = msg.toString();

        // Test parsing.
        Message raw_msg = new Message(st);

        // Test encrypt raw string
        System.out.println(raw_msg.Decrypt(privateKey));
        System.out.println(raw_msg.getContent());

        // Test signature.
        validate = raw_msg.Validate(publicKey);
        System.out.println(validate);
        System.out.println(raw_msg.ValidateCipher(myPublicKey));
    }
};
