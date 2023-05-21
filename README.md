# **RevEng**
Level_Easy

Sau khi tệp `gettingBetter` được tải xuống, tôi chạy file lệnh trên tệp đó để tìm xem đó là loại tệp nào. Truy vấn này cho chúng tôi thấy rằng tệp là tệp thực thi.

![Screenshot from 2023-05-21 09-50-35](https://github.com/nguyenvandat123/flag/assets/127211886/0bfa3d15-6f63-4d9e-bb29-501e235b1288)

Biết được điều đó, tôi đã chạy tệp thực thi và nó hỏi tôi "Please enter the correct passphrase to get the flag:". Tôi đã nhập "paspharase" là một chuỗi bất kì và chương trình cho tôi biết điều đó không chính xác và tôi nên thử lại.

![Screenshot from 2023-05-21 09-51-20](https://github.com/nguyenvandat123/flag/assets/127211886/cdc697a2-dc79-4ebe-8e8d-5bb46899171f)

Vì vậy tôi đã xác định được yêu cầu của thử thách là nhập đúng pass để lấy được flag. Bắt đầu quá trình debug bằng công cụ GDB:

Tôi sẽ sử dụng lệnh sau để sau hàm `main` làm gì:

![Screenshot from 2023-05-21 10-36-41](https://github.com/nguyenvandat123/flag/assets/127211886/2d6f54c4-0b70-4f79-9981-6e640eefac1f)

![Screenshot from 2023-05-21 10-39-01](https://github.com/nguyenvandat123/flag/assets/127211886/50ab3a85-314b-46bc-b8f7-5360c9fb32a5)

Tôi tìm được hàm `check passphrase` tại địa chỉ `0x00005555555551bf ` (có thể đoán được đây là hàm quyết định để ta có được flag) vì vậy tôi đặt break tại địa chỉ này và bắt đầu debug.

![Screenshot from 2023-05-21 10-43-40](https://github.com/nguyenvandat123/flag/assets/127211886/f1ba70fa-f3d5-4305-9b99-74b8d441eafe)

Kết quả:

![Screenshot from 2023-05-21 10-45-59](https://github.com/nguyenvandat123/flag/assets/127211886/947298f7-8db8-49a4-a5f6-2dcfb0193b88)

passphrase đúng sẽ là `She turned me into a newt`

![Screenshot from 2023-05-21 10-48-34](https://github.com/nguyenvandat123/flag/assets/127211886/b3c6f09b-fd23-4009-b01a-184c2604768c)

*byuctf{i_G0t_3etTeR!_1975}*









