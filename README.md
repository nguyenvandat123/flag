# **RevEng**
Level_Easy

Sau khi tệp `gettingBetter` được tải xuống, tôi chạy file lệnh trên tệp đó để tìm xem đó là loại tệp nào. Truy vấn này cho tôi thấy rằng tệp là tệp thực thi.

![Screenshot from 2023-05-21 09-50-35](https://github.com/nguyenvandat123/flag/assets/127211886/0bfa3d15-6f63-4d9e-bb29-501e235b1288)

Biết được điều đó, tôi đã chạy tệp thực thi và nhập "paspharase" là một chuỗi bất kì và chương trình cho tôi biết điều đó không chính xác.

![Screenshot from 2023-05-21 09-51-20](https://github.com/nguyenvandat123/flag/assets/127211886/cdc697a2-dc79-4ebe-8e8d-5bb46899171f)

Vì vậy tôi đã xác định được yêu cầu của thử thách là nhập đúng pass để lấy được flag. Bắt đầu quá trình debug bằng công cụ GDB:

Tôi sẽ sử dụng lệnh sau để biết hàm `main` làm những gì:

![Screenshot from 2023-05-21 10-36-41](https://github.com/nguyenvandat123/flag/assets/127211886/2d6f54c4-0b70-4f79-9981-6e640eefac1f)

![Screenshot from 2023-05-21 10-39-01](https://github.com/nguyenvandat123/flag/assets/127211886/50ab3a85-314b-46bc-b8f7-5360c9fb32a5)

Tôi tìm được hàm `check passphrase` tại địa chỉ `0x00005555555551bf ` (có thể đoán được đây là hàm quyết định để ta có được flag) vì vậy tôi đặt break tại địa chỉ này và bắt đầu debug.

![Screenshot from 2023-05-21 10-43-40](https://github.com/nguyenvandat123/flag/assets/127211886/f1ba70fa-f3d5-4305-9b99-74b8d441eafe)

Kết quả:

![Screenshot from 2023-05-21 10-45-59](https://github.com/nguyenvandat123/flag/assets/127211886/947298f7-8db8-49a4-a5f6-2dcfb0193b88)

passphrase đúng sẽ là `She turned me into a newt`

![Screenshot from 2023-05-21 10-48-34](https://github.com/nguyenvandat123/flag/assets/127211886/b3c6f09b-fd23-4009-b01a-184c2604768c)

*byuctf{i_G0t_3etTeR!_1975}*



- Thực hiện decode dữ liệu thử thách (sử dụng base64) ta được:
```

import java.io.*;
import java.util.*;
import java.time.*;
import java.text.*;
import java.math.*;
public class Deception {
    static FastReader FastReader = new FastReader();
    static BufferedWriter o = new BufferedWriter(new OutputStreamWriter(System.out));
    static PrintWriter pw;

    static char table[] = {
            'd', 'y', 'n', 'm', 'r', '7', '2', '3', '9', '8', 'o', '2', 'm', 'n', 'y', 'l', 'r', 'f', '7', '4', '9',
            '0', '2', '3', 'q', 'y', 'n', 'd', '7', '8', '9', '4', '2', '3', 'y', 'd', '8', '9', 'o', 'q', '7',
            's', 'n', 'g', 'y', 'u', 'i', '2', 'g', 'h', 'u', 'y', 'i', 'c', 'g', 'i', 'k', 'a', 'd', 'l', 'd',
            'g', 'h', 'i', 'w', 'k', 'a', 'l', 'S', 'D', 'H', 'N', 'Q', 'O', '3', '2', '7', 'D', 'Q', '2', 'O',
            '8', 'G', 'D', 'H', '7', '8', 'O', '2', 'Q', 'D', 'N', 'G', 'W', 'U', 'A', 'K', 'D', 'G', 'H', 'X',
            'K', 'J', 'S', 'A', 'G', 'D', '2', 'K', 'S', 'A', 'G', 'I', 'K', 'G', 'I', 'Y', 'K', 'G', 'I', 'K',
            '7', 'i', 'k', 'l', 'f', 'g', '3', 'i', 'k', 'r', 'g', 'f', '3', '8', 'o', '4', '7', 't', 'g', '3',
            '9', '8', 'o', 'f', 'g', 'o', '7', 'i', 'h', 'f', 'k', 'u', 'i', 'a', 'l', 'w', 'e', 'h', 'f', 'i',
            'l', 'w', 'k', 'a', '}', 'h', 'x', 'w', 'l', 'a', 'u', 'k', 'f', 'x', 'n', 'h', 'e', 'a', 'o', 'i',
            'u', 'h', 'x', 'f', 'g', 'a', 'w', 'i', 'o', 'u', 'y', 'g', 'h', 'e', 'a', 'w', '8', 'o', 'n', '7',
            '4', 'w', 'f', '8', 'o', 'n', 'w', 'q', 'g', '7', '8', 'o', '4', 'w', 'a', 'n', 'g', 'h', 'u', 'i',
            'a', 'w', 'e', 'k', '0', 'l', 'f', 'b', 'x', 'c', 'j', 'k', 'a', 's', 'd', 'f', 'b', 'j', 'k', 'a',
            's', 'e', 'f', 'k', 'j', 'a', '7', 'e', 'n', 'f', 'g', 'a', 'i', 'u', 'y', 'w', 'e', 'k', 'f', 'g',
            'y', 'u', 'w', 'e', 'a', 'i', 'o', 'g', 'h', 'x', 'f', 'a', 'e', 'j', 'k', 'w', 'B', 'f', 'w', 'e',
            'a', 'k', 'j', 'f', 'g', 'h', 'a', 'w', '7', 'g', 'v', 'a', 'w', 'u', 'b', 't', '3', '2', 'q', '6',
            '7', '8', 'd', 't', 'b', '3', 'q', '6', '8', 'o', '4', 't', 'q', '7', '8', 'o', 'i', '3', 't', 'r',
            'o', '8', 'c', '7', 'b', 't', '3', '5', 'p', '9', 'q', 't', 'y', '5', 'c', '7', '1', 'b', 'r', 't',
            'c', 'y', '2', '7', '1', '8', 'f', '2', '7', '1', '8', '9', '0', '7', 'n', 'y', '0', '9', '8', 'y',
            'm', 'r', '8', '9', '2', 'm', 'c', '0', '9', '2', 'y', 'i', 'o', 'h', 'u', 'i', 'w', 'h', 'i', 'l',
            'w', 'n', 'h', 'r', 'i', 'u', 'w', 'e', 'k', 'l', 'h', 'n', '8', '2', '7', '0', '3', 'n', 'y', 'r',
            '7', '4', 'j', '3', 'y', 'n', 'r', '7', '8', '3', 'n', 'g', 'h', 'c', 'e', '7', 'u', 'n', 'g', 'c',
            'h', 'o', '3', '7', 'i', '4', 'y', 'h', 'r', 'o', 'i', 'u', 'w', 'e', 'h', 'r', 'i', 'o', 'w', 'n',
            'r', 'u', 'w', 'e', 'i', 'r', 'h', 'n', 'w', 'o', 'u', 'i', 'e', 'n', 'h', 'r', 'i', 'u', 'i', '3',
            'e', 'w', 'n', 'h', 'u', 'i', 'w', 'o', 'h', 'c', 'm', 'r', '7', '8', '4', 'n', 'y', '3', '7', '9',
            '8', '4', '4', '5', '4', '4', '6', 't', '4', '3', '7', '8', '9', '5', '6', '3', '9', '8', '7', 'c',
            'n', 't', '5', 'y', '9', '3', '4', '7', '8', 'n', '5', 't', 'y', 'c', '7', '8', '9', '3', '4', '6',
            'c', '5', '9', '8', '7', '3', '2', '7', '9', 't', 'y', 'b', 'n', '9', 'p', '2', 'y', 'n', 'x', '9',
            '1', '2', 'y', '3', 'r', 'y', 'n', 'd', 'f', '9', '8', 'o', 'r', '7', 'y', 'n', 'm', 'r', 'd', 'o',
            's', '8', '9', '7', 'y', 'n', 'm', 'd', 'r', 'o', 'h', '9', 'q', '7', '0', '4', '2', 'd', 'r', 'y',
            'n', 'm', '9', '3', '2', 'q', '7', '8', '9', 'd', 'y', 'm', '4', 'o', 'q', '8', 't', '9', 'r', 'n',
            'y', 'm', 'f', 'o', 'q', '8', '9', '3', 'f', 'y', 'm', 'n', 'y', '3', 'q', '8', '}', 'o', 'd', 'r',
            'm', 'n', 'y', 'q', '9', '2', '3', '8', '7', 'y', '7', '8', '9', '5', 'y', 'q', '9', 'd', 'o', 'y',
            'l', 'a', 'y', 'a', 'l', 'y', 'd', '9', 'y', 'n', 'l', 'y', 'i', '7', 'N', '7', 'F', 'C', 'N', 'G',
            'H', '3', 'I', 'W', 'Y', 'U', 'T', 'G', 'N', '3', 'I', '7', 'f', '4', 'T', 'G', '8', '7', '3', '6',
            'I', 'W', 'T', '5', 'Y', '7', '8', 'W', '3', '4', 'O', 'N', 'F', 'C', 'B', 'O', 'd', '3', '7', 'N',
            'Y', 'F', 'R', '4', 'N', '7', 'U', 'I', 'Y', 'E', 'K', 'L', 'S', 'H', 'A', 'I', 'U', 'H', 'E', 'R',
            'F', 'U', 'A', 'I', 'W', 'K', 'R', 'N', 'o', 'F', 'H', 'A', 'O', '7', '8', '4', 'Y', '7', 'O', '8',
            'Y', '7', '8', 'O', 'Y', 'N', '7', '8', '4', 'Y', 'N', 'R', 'Q', '7', 'O', '8', '1', '4', '9', 'R',
            'Y', 'N', 'M', 'C', 'Q', '3', 'd', 'R', 'C', 'N', 'Y', '7', 'Q', 'O', 'I', '3', 'U', 'N', 'Y', 'C',
            'H', 'R', 'I', 'L', 'U', 'H', 'I', 'L', 'W', 'A', 'H', 'E', 'R', 'U', '1', 'W', 'L', 'N', 'H', 'C',
            'U', 'I', 'W', '4', 'A', 'N', 'Y', 'H', 'R', 'C', '4', 'A', 'O', '8', '7', '9', 'R', 'Y', 'N', '7',
            'C', 'A', '8', 'Y', 'R', 'C', 'N', '7', '8', 'O', 'A', 'R', 'Y', 'C', 'o', '7', '8', '8', 'O', 'C',
            'R', 'Y', 'N', 'M', 'A', 'C', '7', 'N', 'R', 'H', 'A', 'E', 'I', 'U', 'w', 'O', 'H', 'N', 'R', 'C',
            'A', 'W', 'U', 'I', 'O', 'N', 'H', 'O', 'U', 'I', '3', '7', '8', '6', '2', '8', 'j', '2', '6', '7',
            '8', '9', '1', '6', '4', '7', '8', '9', 'n', '6', 'd', 'x', '9', '8', '7', '2', '3', 'n', 'y', '4',
            '7', '8', '2', 'y', 'x', 'e', '9', 'd', 'h', '2', '7', '3', '8', 'h', 'n', 'x', '7', '8', '9', '2',
            '1', '5', '4', '4', '6', 't', '4', '3', '7', '8', '9', '5', '1', '3', '9', '8', '7', 'p', 'P', 'c',
            'n', 't', '5', 'y', '9', '3', '4', '7', 'd', 'n', '5', 't', 'y', 'c', '7', '8', '9', '3', '4', '6',
            'c', '5', '9', '8', '7', '3', '2', '7', '9', 't', 'y', 'b', 'n', '9', 'p', '2', 'y', 'n', 'x', '9',
            'o', '2', 'y', '3', 'r', 'y', 'n', 'd', 'f', '9', '8', 'o', 'r', '7', 'y', 'n', 'm', 'r', 'd', 'o',
            'q', '8', '9', '7', 'y', 'n', 'm', 'd', 'r', 'o', '8', '9', 'q', '7', '3', '4', '2', 'd', 'r', 'y',
            'n', 'm', 'o', '3', '2', 'q', '7', '8', '9', 'd', 'y', 'm', '4', 'o', 'q', '8', 'p', '9', 'r', 'n',
            'y', 'm', 'f', 'o', 'j', '8', '9', '3', 'f', 'y', 'm', 'n', '7', '3', 'q', '8', '9', 'o', 'd', 'r',
            'm', 'n', 'y', 'q', 'j', '2', '3', '8', '7', 'y', '7', '8', 'l', '5', 'y', 'q', '9', 'd', 'o', 'y',
            'l', 'a', 'y', 'a', 'l', 'y', 'd', '9', '9', 'n', 'l', 'y', 'i', '7', 'N', '7', 'F', 'C', 'N', 'G',
            'H', '3', 'I', 'W', 'Y'
    };

    public static void main(String[] args) throws Exception {
        System.out.println("Welcome to the LMD Machine 3000!");
        System.out.println("Please enter an integer: ");

        int input = readInt();

        System.out.println();

        if (input < 1 || input > table.length) {
            System.out.println("Invalid Input");
            System.exit(0);
        }

        System.out.print("ctf{");

        for (int i = 0, idx = 1; i < 15; ++i) {
            idx = (idx * input) % table.length;
            System.out.print(table[idx]);
        }

        System.out.println("}");
    }

    static int readInt() {return FastReader.readInt();}
    static long readLong() {return FastReader.readLong();}
    static double readDouble() {return FastReader.readDouble();}
    static float readFloat() {return FastReader.readFloat();}
    static String readLine() {return FastReader.readLine();}
    static String next() {return FastReader.next();}
    static boolean readBool() {return FastReader.readBool();}

    static class FastReader extends PrintWriter {
        private final InputStream stream;
        private final byte[] buf = new byte[1 << 16];
        private int curChar, numChars;
        public FastReader() {this(System.in, System.out);}
        public FastReader(InputStream i, OutputStream o) {super(o);stream = i;}
        public FastReader(String i, String o) throws IOException {
            super(new FileWriter(o)); stream = new FileInputStream(i);
        }
        private int readByte() {
            if (numChars == -1) {throw new InputMismatchException();}
            if (curChar >= numChars) {
                curChar = 0;
                try {numChars = stream.read(buf);
                }catch(Exception e){throw new InputMismatchException();}
                if (numChars == -1) {return -1;}
            }
            return buf[curChar++];
        }
        public String next() {
            int c; do {c = readByte();} while (c <= ' ');
            StringBuilder res = new StringBuilder();
            do {res.appendCodePoint(c);c = readByte();} while (c > ' ');
            return res.toString();
        }
        public String readLine() {
            int c; do {c = readByte();} while (isEndLine(c));
            StringBuilder res = new StringBuilder();
            do {res.appendCodePoint(c);c = readByte();} while (c >= ' ');
            return res.toString();
        }
        public int readInt() {
            int c, sgn = 1, res = 0;
            do {c = readByte();} while (c <= ' ');
            if (c == '-') {sgn = -1;c = readByte();}
            do {
                if (c < '0' || c > '9') {throw new InputMismatchException();}
                res = 10 * res + c - '0';c = readByte();
            } while (c > ' ');
            return res * sgn;
        }

        /**
         * Psst
         *
         * https://drive.google.com/file/d/1oDDXyVxYHqdGB6H2bddUxbRL3z39SZb3/view?usp=sharing
         */

        public double readDouble() {return Double.parseDouble(next());}
        public long readLong() {return Long.parseLong(next());}
        public float readFloat() {return Float.parseFloat(next());}
        public boolean readBool() {return Boolean.parseBoolean(next());}
        boolean isEndLine(int c) {return c == '\n' || c == '\r' || c == -1;}
    }
} 
```

- Đoạn mã trên đã quá rõ ràng (0<input<1107 với input là số nguyên)

- Giải pháp:
```
table= [
            'd', 'y', 'n', 'm', 'r', '7', '2', '3', '9', '8', 'o', '2', 'm', 'n', 'y', 'l', 'r', 'f', '7', '4', '9',
            '0', '2', '3', 'q', 'y', 'n', 'd', '7', '8', '9', '4', '2', '3', 'y', 'd', '8', '9', 'o', 'q', '7',
            's', 'n', 'g', 'y', 'u', 'i', '2', 'g', 'h', 'u', 'y', 'i', 'c', 'g', 'i', 'k', 'a', 'd', 'l', 'd',
            'g', 'h', 'i', 'w', 'k', 'a', 'l', 'S', 'D', 'H', 'N', 'Q', 'O', '3', '2', '7', 'D', 'Q', '2', 'O',
            '8', 'G', 'D', 'H', '7', '8', 'O', '2', 'Q', 'D', 'N', 'G', 'W', 'U', 'A', 'K', 'D', 'G', 'H', 'X',
            'K', 'J', 'S', 'A', 'G', 'D', '2', 'K', 'S', 'A', 'G', 'I', 'K', 'G', 'I', 'Y', 'K', 'G', 'I', 'K',
            '7', 'i', 'k', 'l', 'f', 'g', '3', 'i', 'k', 'r', 'g', 'f', '3', '8', 'o', '4', '7', 't', 'g', '3',
            '9', '8', 'o', 'f', 'g', 'o', '7', 'i', 'h', 'f', 'k', 'u', 'i', 'a', 'l', 'w', 'e', 'h', 'f', 'i',
            'l', 'w', 'k', 'a', '}', 'h', 'x', 'w', 'l', 'a', 'u', 'k', 'f', 'x', 'n', 'h', 'e', 'a', 'o', 'i',
            'u', 'h', 'x', 'f', 'g', 'a', 'w', 'i', 'o', 'u', 'y', 'g', 'h', 'e', 'a', 'w', '8', 'o', 'n', '7',
            '4', 'w', 'f', '8', 'o', 'n', 'w', 'q', 'g', '7', '8', 'o', '4', 'w', 'a', 'n', 'g', 'h', 'u', 'i',
            'a', 'w', 'e', 'k', '0', 'l', 'f', 'b', 'x', 'c', 'j', 'k', 'a', 's', 'd', 'f', 'b', 'j', 'k', 'a',
            's', 'e', 'f', 'k', 'j', 'a', '7', 'e', 'n', 'f', 'g', 'a', 'i', 'u', 'y', 'w', 'e', 'k', 'f', 'g',
            'y', 'u', 'w', 'e', 'a', 'i', 'o', 'g', 'h', 'x', 'f', 'a', 'e', 'j', 'k', 'w', 'B', 'f', 'w', 'e',
            'a', 'k', 'j', 'f', 'g', 'h', 'a', 'w', '7', 'g', 'v', 'a', 'w', 'u', 'b', 't', '3', '2', 'q', '6',
            '7', '8', 'd', 't', 'b', '3', 'q', '6', '8', 'o', '4', 't', 'q', '7', '8', 'o', 'i', '3', 't', 'r',
            'o', '8', 'c', '7', 'b', 't', '3', '5', 'p', '9', 'q', 't', 'y', '5', 'c', '7', '1', 'b', 'r', 't',
            'c', 'y', '2', '7', '1', '8', 'f', '2', '7', '1', '8', '9', '0', '7', 'n', 'y', '0', '9', '8', 'y',
            'm', 'r', '8', '9', '2', 'm', 'c', '0', '9', '2', 'y', 'i', 'o', 'h', 'u', 'i', 'w', 'h', 'i', 'l',
            'w', 'n', 'h', 'r', 'i', 'u', 'w', 'e', 'k', 'l', 'h', 'n', '8', '2', '7', '0', '3', 'n', 'y', 'r',
            '7', '4', 'j', '3', 'y', 'n', 'r', '7', '8', '3', 'n', 'g', 'h', 'c', 'e', '7', 'u', 'n', 'g', 'c',
            'h', 'o', '3', '7', 'i', '4', 'y', 'h', 'r', 'o', 'i', 'u', 'w', 'e', 'h', 'r', 'i', 'o', 'w', 'n',
            'r', 'u', 'w', 'e', 'i', 'r', 'h', 'n', 'w', 'o', 'u', 'i', 'e', 'n', 'h', 'r', 'i', 'u', 'i', '3',
            'e', 'w', 'n', 'h', 'u', 'i', 'w', 'o', 'h', 'c', 'm', 'r', '7', '8', '4', 'n', 'y', '3', '7', '9',
            '8', '4', '4', '5', '4', '4', '6', 't', '4', '3', '7', '8', '9', '5', '6', '3', '9', '8', '7', 'c',
            'n', 't', '5', 'y', '9', '3', '4', '7', '8', 'n', '5', 't', 'y', 'c', '7', '8', '9', '3', '4', '6',
            'c', '5', '9', '8', '7', '3', '2', '7', '9', 't', 'y', 'b', 'n', '9', 'p', '2', 'y', 'n', 'x', '9',
            '1', '2', 'y', '3', 'r', 'y', 'n', 'd', 'f', '9', '8', 'o', 'r', '7', 'y', 'n', 'm', 'r', 'd', 'o',
            's', '8', '9', '7', 'y', 'n', 'm', 'd', 'r', 'o', 'h', '9', 'q', '7', '0', '4', '2', 'd', 'r', 'y',
            'n', 'm', '9', '3', '2', 'q', '7', '8', '9', 'd', 'y', 'm', '4', 'o', 'q', '8', 't', '9', 'r', 'n',
            'y', 'm', 'f', 'o', 'q', '8', '9', '3', 'f', 'y', 'm', 'n', 'y', '3', 'q', '8', '}', 'o', 'd', 'r',
            'm', 'n', 'y', 'q', '9', '2', '3', '8', '7', 'y', '7', '8', '9', '5', 'y', 'q', '9', 'd', 'o', 'y',
            'l', 'a', 'y', 'a', 'l', 'y', 'd', '9', 'y', 'n', 'l', 'y', 'i', '7', 'N', '7', 'F', 'C', 'N', 'G',
            'H', '3', 'I', 'W', 'Y', 'U', 'T', 'G', 'N', '3', 'I', '7', 'f', '4', 'T', 'G', '8', '7', '3', '6',
            'I', 'W', 'T', '5', 'Y', '7', '8', 'W', '3', '4', 'O', 'N', 'F', 'C', 'B', 'O', 'd', '3', '7', 'N',
            'Y', 'F', 'R', '4', 'N', '7', 'U', 'I', 'Y', 'E', 'K', 'L', 'S', 'H', 'A', 'I', 'U', 'H', 'E', 'R',
            'F', 'U', 'A', 'I', 'W', 'K', 'R', 'N', 'o', 'F', 'H', 'A', 'O', '7', '8', '4', 'Y', '7', 'O', '8',
            'Y', '7', '8', 'O', 'Y', 'N', '7', '8', '4', 'Y', 'N', 'R', 'Q', '7', 'O', '8', '1', '4', '9', 'R',
            'Y', 'N', 'M', 'C', 'Q', '3', 'd', 'R', 'C', 'N', 'Y', '7', 'Q', 'O', 'I', '3', 'U', 'N', 'Y', 'C',
            'H', 'R', 'I', 'L', 'U', 'H', 'I', 'L', 'W', 'A', 'H', 'E', 'R', 'U', '1', 'W', 'L', 'N', 'H', 'C',
            'U', 'I', 'W', '4', 'A', 'N', 'Y', 'H', 'R', 'C', '4', 'A', 'O', '8', '7', '9', 'R', 'Y', 'N', '7',
            'C', 'A', '8', 'Y', 'R', 'C', 'N', '7', '8', 'O', 'A', 'R', 'Y', 'C', 'o', '7', '8', '8', 'O', 'C',
            'R', 'Y', 'N', 'M', 'A', 'C', '7', 'N', 'R', 'H', 'A', 'E', 'I', 'U', 'w', 'O', 'H', 'N', 'R', 'C',
            'A', 'W', 'U', 'I', 'O', 'N', 'H', 'O', 'U', 'I', '3', '7', '8', '6', '2', '8', 'j', '2', '6', '7',
            '8', '9', '1', '6', '4', '7', '8', '9', 'n', '6', 'd', 'x', '9', '8', '7', '2', '3', 'n', 'y', '4',
            '7', '8', '2', 'y', 'x', 'e', '9', 'd', 'h', '2', '7', '3', '8', 'h', 'n', 'x', '7', '8', '9', '2',
            '1', '5', '4', '4', '6', 't', '4', '3', '7', '8', '9', '5', '1', '3', '9', '8', '7', 'p', 'P', 'c',
            'n', 't', '5', 'y', '9', '3', '4', '7', 'd', 'n', '5', 't', 'y', 'c', '7', '8', '9', '3', '4', '6',
            'c', '5', '9', '8', '7', '3', '2', '7', '9', 't', 'y', 'b', 'n', '9', 'p', '2', 'y', 'n', 'x', '9',
            'o', '2', 'y', '3', 'r', 'y', 'n', 'd', 'f', '9', '8', 'o', 'r', '7', 'y', 'n', 'm', 'r', 'd', 'o',
            'q', '8', '9', '7', 'y', 'n', 'm', 'd', 'r', 'o', '8', '9', 'q', '7', '3', '4', '2', 'd', 'r', 'y',
            'n', 'm', 'o', '3', '2', 'q', '7', '8', '9', 'd', 'y', 'm', '4', 'o', 'q', '8', 'p', '9', 'r', 'n',
            'y', 'm', 'f', 'o', 'j', '8', '9', '3', 'f', 'y', 'm', 'n', '7', '3', 'q', '8', '9', 'o', 'd', 'r',
            'm', 'n', 'y', 'q', 'j', '2', '3', '8', '7', 'y', '7', '8', 'l', '5', 'y', 'q', '9', 'd', 'o', 'y',
            'l', 'a', 'y', 'a', 'l', 'y', 'd', '9', '9', 'n', 'l', 'y', 'i', '7', 'N', '7', 'F', 'C', 'N', 'G',
            'H', '3', 'I', 'W', 'Y']
s=""
file = open("output.txt", "w")
for input_ in range(1,len(table)+1):
    idx=1
    s+="ctf{"
    for i in range(0,15):
        idx = (idx * input_) % len(table)
        s+=(table[idx])
    s+="}"
    file.write(str(input_)+ "  "+s+"\n")
    s=""
file.close()
```
- Kết quả tạo một tệp output.txt chứa 1107 flag
- Giờ đơn giản nhất đỡ suy nghĩ nhiều ta submit 1107 lần:)))))) 
- Ta sử dụng https://www.dcode.fr/brainfuck-language để decode dữ liệu từ link gg drive từ đề bài:

![image](https://github.com/nguyenvandat123/flag/assets/127211886/20caa2e2-44ad-4bc5-8375-2d6cf8844953)

ta có một gợi ý `Unix Epoch`
-Tra cứu thông tin trên google vơi từ khóa `Unix Epoch` ta tìm được thông tin *Thời gian Unix (tiếng Anh: Unix time, Epoch time hay POSIX time) là hệ thống mô tả một điểm trong thời gian. Thời gian Unix được định nghĩa bằng số giây kể từ 00:00:00 theo giờ Phối hợp Quốc tế (UTC) ngày 1 tháng 1 năm 1970[1], trừ đi giây nhuận.*
- Thử với tệp output.txt thông tin năm `1970` (kết hợp challenge hint) ta được flag ctf{hjwilj111970djs} với input=571  




- Check file và chạy thử 

![Screenshot from 2023-06-04 03-57-21](https://github.com/nguyenvandat123/flag/assets/127211886/87d9d9c7-1ebd-44e6-a0a6-ad9f50154430)

- Khái quát sơ thử thách này: đây là một thử thách có vẻ không khó lắm, thử thách yêu cầu nhập `password` đúng (có lẽ đó là flag).
- Tôi sẽ sử dụng công cụ IDA để giải quyết:
   - Load file vào IDA và như thường lệ tôi sẽ check xem những `strings` được sử dụng, từ đó xem chúng như là gợi ý tìm đến đoạn code trọng tâm để dễ dàng giải quyết vấn đề

![image](https://github.com/nguyenvandat123/flag/assets/127211886/f59c7196-d5ed-4c59-a025-8151114934fc)


![image](https://github.com/nguyenvandat123/flag/assets/127211886/4275a53a-9ef6-48bd-ad07-163a835189bc)

- Thật thất vọng không đúng như dự đoán trước đó:)))), tôi đã không tìm được đoạn code chứa chuỗi `Incorrect password`
- Hướng giải khác, tôi tìm hàm `main` và xem chúng làm những gì:
   - Bằng những thao tác đơn giản tôi tìm được đoạn mã (vì đoạn mã asm khá dài nên tôi sẽ viết lại bằng code c++): 
 - Thử thách:       
```
#include <iostream>
#include <string>
using namespace std;
int main() {
    const unsigned char hexString[] = {
        0x0, 0x63, 0x17, 0x71, 0x0A, 0x3E, 0x50, 0x24, 0x15,
        0x4A, 0x2E, 0x1F, 0x6C, 0x58, 0x2B, 0x46, 0x19,
        0x74, 0x47, 0x73, 0x00, 0x75, 0x07, 0x34, 0x47,
        0x18, 0x7E, 0x0A, 0x7D, 0x0
    };

    int length = sizeof(hexString) / sizeof(hexString[0]);
    string input;
    cout<<"Enter the password:"<<endl;
    cin>>input;
    for (int i=0;i<length-1;i++)
    {
        if (char(hexString[i]^hexString[i+1])!=input[i])
        {
           cout<<"Incorrect password"<<endl;
           return 0;
        }
    }
    cout<<"That's correct!";
    return 0;
}
```
- Giải quyết:
```
#include <iostream>
#include <string>
using namespace std;
int main() {
    const unsigned char hexString[] = {
        0x0, 0x63, 0x17, 0x71, 0x0A, 0x3E, 0x50, 0x24, 0x15,
        0x4A, 0x2E, 0x1F, 0x6C, 0x58, 0x2B, 0x46, 0x19,
        0x74, 0x47, 0x73, 0x00, 0x75, 0x07, 0x34, 0x47,
        0x18, 0x7E, 0x0A, 0x7D, 0x0
    };

    int length = sizeof(hexString) / sizeof(hexString[0]);
    string output="";
    for (int i=0;i<length-1;i++)
    {
        output+=char(hexString[i]^hexString[i+1]);
    }
    cout<<output;
    return 0;
}
```
ctf{4nt1_d1s4sm_m34sur3s_ftw}








