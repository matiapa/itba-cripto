import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Stats {

    public static void main(String[] args) throws IOException {
        File originalFile = new File("tmp/neo.bmp");
        File tamperedFile = new File("tmp/in/neo_lsb1.bmp");

        FileInputStream is = new FileInputStream(originalFile);
        byte[] originalBytes = new byte[(int) originalFile.length()];
        is.read(originalBytes);

        is = new FileInputStream(tamperedFile);
        byte[] tamperedBytes = new byte[(int) tamperedFile.length()];
        is.read(tamperedBytes);

        float ecm = 0, tampered = 0;
        for(int i=0; i<originalBytes.length; i++) {
            ecm += Math.pow(tamperedBytes[i] - originalBytes[i], 2);
            if(ecm > 0) tampered++;
        }
        ecm /= originalBytes.length;

        System.out.println(ecm);
        System.out.println(tampered);
    }

}
