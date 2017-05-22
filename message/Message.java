package message;

import java.util.*;
import javax.crypto.*;
import java.security.*;
import message.encryptionutil.*;

public class Message{
    private int number_of_signature = 0;
    private String message;
    private List <String> signature = new ArrayList <String> ();
    private String summary = "";

    public Message(){}

    public Message(String msg) throws Exception{
        Scanner sc = new Scanner(msg);

        // Parse the summary
        int summary_length = sc.nextInt();
        sc.useDelimiter("");
        sc.next();
        for(int i = 0; i < summary_length; i++){
            summary = summary + sc.next().charAt(0);
        }

        //Parse the signatures
        sc.useDelimiter(" ");
        number_of_signature = sc.nextInt();

        sc.useDelimiter("");
        sc.next();
        for(int j = 0; j < number_of_signature; j++){
            String sign = "";
            for(int i = 0; i < 256; i++){
                char c = sc.next().charAt(0);
                sign = sign + c;
            }
            signature.add(sign);
        }

        // Read the cypher text.
        message = "";
        while(sc.hasNext()){
            message = message + sc.next();
        }

    }

    public String toString(){
        String result = summary.length() + " " + summary;
        result = result + number_of_signature + " ";
        for(String sign:signature){
            result = result + sign;
        }
        return result + message;
    }

    public KeyPair Generate() throws Exception{
        return EncryptionUtil.generate();
    }

    public void Encrypt(String content,PublicKey key) throws Exception{
        message = EncryptionUtil.encrypt(content,key);
        summary = EncryptionUtil.summary(content);
        summary = EncryptionUtil.encrypt(summary,key);
    }

    public String Decrypt(PrivateKey key) throws Exception{
        return EncryptionUtil.decrypt(message,key);
    }

    public String Summary(PrivateKey key) throws Exception{
        return EncryptionUtil.decrypt(summary,key);
    }

    public void Sign(PrivateKey key) throws Exception{
        signature.add(EncryptionUtil.sign(message,key));
        number_of_signature = number_of_signature + 1;
    }

    public boolean Validate(PublicKey key) throws Exception{
        for(String sign: signature){
            if(EncryptionUtil.verify(message,key,sign)) return true;
        }
        return false;
    }
}
