import java.util.*;
import javax.crypto.*;
import java.security.*;

public class Main{
    public static void main(String [] args){
        Scanner sc = new Scanner(System.in);
        int n = sc.nextInt();
        int m = sc.nextInt();
        int [] d = new int [n];
        for(int i = 0; i < m; i++){
            int x = sc.nextInt() - 1;
            int y = sc.nextInt() - 1;
            d[x]++; d[y]++;
        }
        if(allEven(n,d)) {
            System.out.println("YES");
        } else{
            System.out.println("NO");
        }
        return;
    }

    public static boolean allEven(int n,int [] d){
        for(int i = 0; i < n; i++){
            if ((d [i] & 1) == 1) return false;
        }
        return true;
    }
}
