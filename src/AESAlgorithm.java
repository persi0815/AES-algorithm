import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

public class AESAlgorithm {

    // 학번과 이름을 이진수로 변환하여 AES 128비트 키 생성
    public static SecretKey generateKey(String studentId, String name) {
        // 학번 10문자 + 이름 6문자 = 16문자
        String studentIdBinary = stringToBinary(studentId); // 학번을 이진수로 변환
        String nameBinary = stringToBinary(name);           // 이름을 이진수로 변환

        // 128비트(16바이트) AES 키 만들기
        String keyBinary = (studentIdBinary + nameBinary).substring(0, 128); // 128비트로 자름
        byte[] keyBytes = new byte[16]; // 128비트 = 16바이트
        for (int i = 0; i < 16; i++) {
            keyBytes[i] = (byte) Integer.parseInt(keyBinary.substring(i * 8, (i + 1) * 8), 2);
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    // 문자열을 이진수로 변환
    public static String stringToBinary(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append(String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0"));
        }
        return result.toString();
    }

    // AES 암호화
    public static byte[] aesEncrypt(byte[] plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding"); // NoPadding 사용
        if (plaintext.length % 16 != 0) {
            throw new IllegalArgumentException("Plaintext length must be a multiple of 16 bytes (128 bits) with NoPadding.");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext); // 평문을 바이트 배열로 전달
    }

    // AES 복호화
    public static String aesDecrypt(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding"); // NoPadding 사용
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes).trim(); // 복호화된 결과 반환
    }

    // 고정된 IvParameterSpec 생성 (고정된 초기화 벡터)
    public static IvParameterSpec generateFixedIv() {
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x00); // 고정된 값으로 초기화
        return new IvParameterSpec(iv);
    }

    // 암호키의 첫 번째 비트를 변경 (AES 128비트 키는 항상 128비트로 유지)
    public static byte[] flipFirstBitInKey(byte[] key) {
        byte[] modifiedKey = key.clone();
        modifiedKey[0] = (byte) (modifiedKey[0] ^ 0x80); // 첫 번째 비트 변경 (XOR)
        return modifiedKey;
    }

    // 평문의 첫 번째 비트를 변경
    public static byte[] flipFirstBitInPlaintext(byte[] plaintext) {
        byte[] modifiedPlaintext = plaintext.clone();
        modifiedPlaintext[0] = (byte) (modifiedPlaintext[0] ^ 0x80); // 첫 번째 비트 변경 (XOR)
        return modifiedPlaintext;
    }

    // 바이트 배열을 16진수로 변환하는 메소드
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b)); // 각 바이트를 16진수 2자리로 변환
        }
        return sb.toString();
    }

    // 바이트 배열을 128비트 2진수 문자열로 변환하는 메소드
    public static String byteArrayToBinaryString(byte[] bytes) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : bytes) {
            binaryString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0')); // 8자리 2진수로 변환
        }
        return binaryString.toString();
    }

    // 128비트짜리 2진수 문자열 간의 비트 차이 계산
    public static int calculateBitDifferenceFromBinaryStrings(String binaryStr1, String binaryStr2) {
        int diffCount = 0;
        for (int i = 0; i < binaryStr1.length(); i++) {
            if (binaryStr1.charAt(i) != binaryStr2.charAt(i)) {
                diffCount++;
            }
        }
        return diffCount;
    }

    public static void main(String[] args) throws Exception {
        // 학번과 이름
        String studentId = "2022126061";
        String name = "YANGJW";

        // 평문
        String plaintext = "ABCDEFGHIJKLMNOP";
        byte[] plaintextBytes = plaintext.getBytes();

        if (plaintextBytes.length != 16) {
            throw new IllegalArgumentException("Plaintext must be exactly 16 bytes (128 bits) long.");
        }

        // AES 암호키 생성
        SecretKey key = generateKey(studentId, name);

        // 평문 암호화 (고정된 IV 사용)
        IvParameterSpec iv = generateFixedIv();
        byte[] ciphertext = aesEncrypt(plaintextBytes, key, iv);

        // 암호화 결과 출력
        System.out.println("암호화된 텍스트 (16진수): " + bytesToHex(ciphertext));

        // 복호화
        String decryptedText = aesDecrypt(ciphertext, key, iv);
        System.out.println("복호화된 텍스트: " + decryptedText);

        // 평문 첫 번째 비트 변경 후 암호화
        byte[] flippedPlaintextBytes = flipFirstBitInPlaintext(plaintextBytes);
        byte[] flippedCiphertext = aesEncrypt(flippedPlaintextBytes, key, iv);
        System.out.println("첫 번째 비트 바꾼 평문 암호화 텍스트 (16진수): " + bytesToHex(flippedCiphertext));

        // 암호키의 첫 번째 비트 변경 후 암호화
        byte[] keyBytes = key.getEncoded();
        byte[] flippedKeyBytes = flipFirstBitInKey(keyBytes);
        SecretKey flippedKey = new SecretKeySpec(flippedKeyBytes, "AES");

        byte[] flippedKeyCiphertext = aesEncrypt(plaintextBytes, flippedKey, iv);
        System.out.println("첫 번째 비트 바꾼 키로 암호화된 텍스트 (16진수): " + bytesToHex(flippedKeyCiphertext));

        // 바이트 배열을 2진수 문자열로 변환
        String binaryCiphertext = byteArrayToBinaryString(ciphertext);
        String binaryFlippedCiphertext = byteArrayToBinaryString(flippedCiphertext);
        String binaryFlippedKeyCiphertext = byteArrayToBinaryString(flippedKeyCiphertext);

        // 비트 차이 계산
        int plaintextBitDiff = calculateBitDifferenceFromBinaryStrings(binaryCiphertext, binaryFlippedCiphertext);
        System.out.println("평문 첫 비트 변경 후 비트 차이: " + plaintextBitDiff + " 비트");

        int keyBitDiff = calculateBitDifferenceFromBinaryStrings(binaryCiphertext, binaryFlippedKeyCiphertext);
        System.out.println("암호키 첫 비트 변경 후 비트 차이: " + keyBitDiff + " 비트");
    }
}
