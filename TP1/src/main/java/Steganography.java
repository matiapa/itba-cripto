import org.apache.commons.lang3.ArrayUtils;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Steganography {

    static String FILES_DIR = "tmp/";

    public static void embed(File hostFile, File payloadFile, String outFileName, EncodeMode encodeMode) throws IOException {
        if (!hostFile.getName().split("\\.")[1].equals("bmp"))
            throw new RuntimeException("Host file must be a BMP");

        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;

        // Check that host file is big enough

        String extensionName = payloadFile.getName().split("\\.")[1];
        extensionName = String.format(".%s", extensionName);

        int minSize = (int) (4 + payloadFile.length() + extensionName.length());
        minSize *= Math.floorDiv(8, n);

        if(hostFile.length() <  minSize)
            throw new RuntimeException(String.format("Host file must have at least %d bytes", minSize));

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] hostBytes = new byte[(int) hostFile.length()];
        is.read(hostBytes);

        // Get payload metadata

        int payloadSize = (int) payloadFile.length();
        byte[] payloadSizeBytes = ByteBuffer.allocate(4).putInt(payloadSize).array();

        byte[] extensionNameBytes = ArrayUtils.addAll(extensionName.getBytes(), new byte[]{0});

        // Get payload data

        is = new FileInputStream(payloadFile);
        byte[] payloadDataBytes = new byte[payloadSize];
        is.read(payloadDataBytes);

        // Encode payload data with metadata

        byte[] extendedPayload = ArrayUtils.addAll(payloadSizeBytes, payloadDataBytes);
        extendedPayload = ArrayUtils.addAll(extendedPayload, extensionNameBytes);

        LSBEncode(extendedPayload, hostBytes, n);

        // Write tampered host bytes

        FileOutputStream os = new FileOutputStream(FILES_DIR.concat(outFileName));
        os.write(hostBytes);
    }

    public static void extract(File hostFile, String outFileName, EncodeMode encodeMode) throws IOException {
        if (!hostFile.getName().split("\\.")[1].equals("bmp"))
            throw new RuntimeException("Host file must be a BMP");

        int n = encodeMode== EncodeMode.LSB1 || encodeMode== EncodeMode.LSBI ? 1 : 4;

        // Read host file

        FileInputStream is = new FileInputStream(hostFile);
        byte[] scrBytes = new byte[(int) hostFile.length()];
        is.read(scrBytes);

        // Decode payload data with metadata

        byte[] targetBytes = new byte[(int) Math.ceil(hostFile.length() / (8.0 / n))];
        LSBDecode(scrBytes, targetBytes, n);

        // Get payload metadata

        int payloadSize = ByteBuffer.wrap(targetBytes, 0, 4).getInt();

        List<Byte> extensionNameBytes = new ArrayList<>();
        for(int i=4+payloadSize; targetBytes[i] != 0; i++)
            extensionNameBytes.add(targetBytes[i]);
        String extensionName = new String(ArrayUtils.toPrimitive(extensionNameBytes.toArray(new Byte[0])), StandardCharsets.UTF_8);

        // Write payload data into output file

        String filename = String.format("%s%s%s", FILES_DIR, outFileName, extensionName);
        File outputFile = new File(filename);
        FileOutputStream os = new FileOutputStream(outputFile);

        os.write(targetBytes, 4, payloadSize);
    }


    static void LSBEncode(byte[] payload, byte[] host, int n) {
        int payloadBit=0, hostBit=8-n;
        while(payloadBit < payload.length * 8) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(payload, payloadBit++, host, i);
            hostBit += 8;
        }
    }


    static void LSBDecode(byte[] host, byte[] payload, int n) {
        int payloadBit=0, hostBit=8-n;
        while(payloadBit < payload.length * 8) {
            for(int i=hostBit; i<hostBit+n; i++)
                copyBit(host, i, payload, payloadBit++);
            hostBit += 8;
        }
    }

    static void copyBit(byte[] src, int srcBitN, byte[] target, int targetBitN) {
        int mask = 1 << (7 - srcBitN % 8);
        int bit = (src[srcBitN / 8] & mask) >> (7 - srcBitN % 8);

        if(bit == 1)
            target[targetBitN / 8] |= 1 << (7 - targetBitN % 8);
        else
            target[targetBitN / 8] &= ~(1 << (7 - targetBitN % 8));
    }

    public static void main(String[] args) throws IOException {
        File hostFile = new File(FILES_DIR.concat("host.bmp"));
        File payloadFile = new File(FILES_DIR.concat("payload.bin"));
        embed(hostFile, payloadFile, "host_tampered.bmp", EncodeMode.LSB4);

        // TODO: Mostrar error si el tamanio del host es insuficiente
        // TODO: Mostrar error si el host posee compresion
        // TODO: Agregar parsing de argumentos y valores default

        File hostTamperedFile = new File(FILES_DIR.concat("host_tampered.bmp"));
        extract(hostTamperedFile, "payload_recovered", EncodeMode.LSB4);
    }

    // HT: FF x31 FF  FF x8 FF FF FF FF
    // PL: 0  x31 1   0  x8 0  0  1  0
    // OT: FE x31 FF  FE x8 FE FE FF FE

    public enum EncodeMode {LSB1, LSB4, LSBI}

}
