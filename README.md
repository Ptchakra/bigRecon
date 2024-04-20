# I. Installation.

## 1. Cài đặt Docker.

_On Windowns_:

- Install Docker Desktop [theo hướng dẫn](https://docs.docker.com/desktop/install/windows-install/) .
- Run `docker-compose -f ./docker-compose.yml up -d --build db web redis celery celery-beat` to start tool.

_On Linux_:

- [Install docker](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04) and [docker-compose](https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-compose-on-ubuntu-20-04).

_On MacOS_

- Install Docker Desktop [theo hướng dẫn](https://docs.docker.com/desktop/install/mac-install/).
- Run `make up` OR to start tool.

## 2. Start tool.

- Chạy lệnh `docker-compose -f ./docker-compose.yml up -d --build db web redis celery celery-beat` (hoặc `make up` nếu đã cài make) để start tool.
- Chờ các container start xong thì chạy lệnh `docker-compose -f ./docker-compose.yml exec web python3 manage.py createsuperuser` (hoặc `make superuser`)

## 3. Truy cập tool.

Truy cập vào [http://localhost:8000](http://localhost:8000) để truy cập tool và đăng nhập bằng tài khoản vừa tạo ở bước 2.

# II. How to use?

## 1. Tool workflow

Tool sẽ bao gồm các bước scan: Subdomain (list danh sách domain và server ip), Port, Fuzzing file trên server, Fetch endpoint, Vulnerability scan.

Config về các bước scan (chạy những bước scan nào, công cụ, wordlist,...) sẽ được tổ hợp thành 1 workflow (gọi là Scan Engine).

_Scan engine page_
![scan-engine-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/scan-engine-page.png)

_Scan engine config page_
![scan-engine-config-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/scan-engine-config.png)

## 2. Cách sử dụng

- Thêm target domain tại `Targets > add target`
  ![add-target-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/add-target-page.png)
- Tại trang `List target` chọn phương thức scan cho domain (chạy ngay lập tức hoặc schedule). Sau đó chọn scan engine (luồng chạy).
  ![target-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/target-page.png)
- Xem kết quả tại trang `History`
  ![history-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/scan-history-page.png)
  ![scan-result-detail](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/scan-result-detail.png)

# III. Vuln Scan

Hiện tool đang scan vuln với [jaeles.](https://github.com/jaeles-project/jaeles) Công cụ cho phép tự tạo signature cho Jeales tại `Signatures`. Hướng dẫn tạo Signature [tại đây](https://jaeles-project.github.io/signatures/).
![add-signature-page](https://raw.githubusercontent.com/Ptchakra/bigRecon/main/wiki/add-signature-page.png)

# IV. TODO

- Scan Vuln với nuclei và xray
- Fix Aquatone
