# Linux---Epoll-Web-Server----------
 Linux下基于Epoll Web Server的设计实现个人通讯录

 
存在问题
	输入正确的用户名和密码后进入的博客无法进行get/post 	
	即无法正确进行班级信息管理输入
	只有进入http://localhost:8080/才能成功实现通讯录功能			
	安全认证那里按要求是输错密码则重试，重试次数多了再返回401
解决方案
	修改函数逻辑
	设置计数器

 Linux终端输入
gcc -o webserver http.c -lpthread -lssl -lcrypto -ljson-c
	（可能显示没有安装）
./webserver
	再打开火狐浏览器输入
	http://localhost:8080/
	进入博客，在班级信息管理中输入文件名等信息。会自动创建一个.txt文件并读入
	输入	http://localhost:8080/secured
	后输入用户名和密码，初始用户名：jyt
			     		初始密码：111
	如果输错了则重新输入。
	如果用户名和密码输入全为空，则显示401
	若输入	http://localhost:8080/adsadas	等错误
	则返回404 not found




