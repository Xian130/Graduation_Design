#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <mysql/mysql.h>
#include <queue>
#include <random>
#include <cstdlib>
#include <set>
#include <alibabacloud/core/AlibabaCloud.h>
#include <alibabacloud/core/CommonRequest.h>
#include <alibabacloud/core/CommonClient.h>
#include <alibabacloud/core/CommonResponse.h>
#include <map>

using namespace std;
using namespace AlibabaCloud;

static std::string keys;
MYSQL *sql;
static char position = 0;//剩余座位
static char value1 = 0;//可预约座位
static string value2 = "000000000000";
static string curkey;
static int value3 = 0;
const unsigned short GOAL = 0xaa55; // 你可以根据实际协议修改
const char device_id = 0x02; // 设备ID，按实际需求设置
string code;

std::queue<char> que;
std::set<string> se;
std::set<string> sed;
std::map<string,int> mp;


//扫描二维码 分配座位 position -1 映射，

enum class tran_type :char{
    REQUC, // 请求连接
    REQUC_SUCCESS, // 请求连接成功
    REQUC_LOAD, // 请求连接登录
    REQUC_LOAD_SUCCESS,
    REQUC_LOAD_FAIL_NOUSER, // 请求连接失败，用户不存在
    REQUC_LOAD_FAIL_PWDERR, // 请求连接失败，密码错误
    CONNECTING, // 正常通信
    DISCONNECT, // 断开连接
    SMSREQUC,        // 验证码请求
    SMSREPLY,         // 验证码返回
    SMSREQUC_FAIL,     // 验证码错误
    PASSWORDSET,       // 密码上传
    PASSWORDPASS,       //密码设置成功
    QRCODE_UPLOAD,   // 二维码数据上传
    QRCODE_VERIFY_SUCCESS,//二维码数据验证成功
    QRCODE_VERIFY_FAIL,//二维码数据验证失败
    PASSWORDRESET,
    MESSERROR
};

struct me{
    tran_type p;
    std::string message;
};

//预约功能
std::string joint_message(unsigned short lengths,int mess_id,char mess_type,std::string curs_message);
me split_message(std::string curs_message);
void handleErrors() ;
std::string base64_encode(const std::vector<unsigned char>& binary_data);
std::vector<unsigned char> base64_decode(const std::string& base64_data);
std::string aes_encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key);
std::string aes_decrypt(const std::vector<unsigned char>& pre_ciphertext,const std::vector<unsigned char>& key);
void init_ssl();
std::vector<unsigned char> string_to_vector(std::string keys);
void solve_mess(std::string mess,int client_socket);
void handle_client(int client_socket);
std::string sql_get(int index,std::string id);
void send_sms(std::string id,std::string code);
std::string generateRandomNumberString(int length) ;
bool sql_insert_password(std::string id,std::string password);//添加用户密码，修改用户密码

std::string generateRandomNumberString(int length) {
    std::string result;
    std::random_device rd; // 随机设备
    std::mt19937 gen(rd()); // 随机数生成器
    std::uniform_int_distribution<> dis(0, 9); // 生成0到9之间的随机数

    for (int i = 0; i < length; ++i) {
        result += std::to_string(dis(gen)); // 生成随机数字并追加到字符串
    }

    return result;
}



bool sql_insert_password(string m_id, string m_password){
    
    char query[256];
    snprintf(query, sizeof(query), "INSERT INTO users  VALUES ('%s','%s')", m_id.c_str(), m_password.c_str());
    //
    //"INSERT INTO users  VALUES ('%s','%s')"
    if (mysql_query(sql, query)) {
        if (mysql_errno(sql) == 1062) { // 1062是MySQL中重复键的错误码
            fprintf(stderr, "Error: Duplicate entry for id %s\n", m_id.c_str());
        } else {
            fprintf(stderr, "Error: %s\n", mysql_error(sql));
        }
    } else {
        printf("Data inserted successfully.\n");
        return 1;
    }
    return 0;
}

void send_sms(std::string id,std::string code){
     AlibabaCloud::InitializeSdk();
    AlibabaCloud::ClientConfiguration configuration( "cn-qingdao" );
    // specify timeout when create client.
    configuration.setConnectTimeout(1500);
    configuration.setReadTimeout(4000);
    // Please ensure that the environment variables ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET are set.
    cout <<"!!!!!!"<<endl;
    AlibabaCloud::Credentials credential( "LTAI5tPAN9zX2bV8mXWWnPgt", "SD9k8eotRDbZ6rn2j5KegXyg9GOsef");
    /* use STS Token
    credential.setSessionToken( getenv("ALIBABA_CLOUD_SECURITY_TOKEN") );
    */
    cout <<"xxxxx"<<endl;
    AlibabaCloud::CommonClient client( credential, configuration );
    AlibabaCloud::CommonRequest request(AlibabaCloud::CommonRequest::RequestPattern::RpcPattern);
    request.setHttpMethod(AlibabaCloud::HttpRequest::Method::Post);
    request.setDomain("dysmsapi.aliyuncs.com");
    request.setVersion("2017-05-25");
    request.setQueryParameter("Action", "SendSms");
    request.setQueryParameter("SignName", "阿里云短信测试");
    request.setQueryParameter("TemplateCode", "SMS_154950909");
    request.setQueryParameter("PhoneNumbers", id);
    request.setQueryParameter("TemplateParam", "{\"code\":\""+code+"\"}");

    auto response = client.commonResponse(request);
    if (response.isSuccess()) {
        printf("request success.\n");
        printf("result: %s\n", response.result().payload().c_str());
    } else {
        printf("error: %s\n", response.error().errorMessage().c_str());
        printf("request id: %s\n", response.error().requestId().c_str());
    }

    AlibabaCloud::ShutdownSdk();
}

inline std::string num_to_hex(int  nums,int lengths){
    std::ostringstream oss;
    oss << std::hex << std::uppercase; // 设置为十六进制并使用大写字母
    oss << std::setw(lengths) << std::setfill('0') << nums;
    std::string ret = oss.str();
    return ret;
}

inline int hex_to_int(std::string hexStr,int index,int fixedLength){
    std::string segment = hexStr.substr(index, fixedLength);
    int decimalValue;
    std::istringstream segmentStream(segment);
    segmentStream >> std::hex >> decimalValue;
    return decimalValue;
}


void sql_insert(){
	
}

std::string sql_get(int index,std::string id){
	if(index==0){
	// 查询数据库
	std::string result = "";
	std::string query = "SELECT password FROM users WHERE id='" + id + "';";
	if (mysql_query(sql, query.c_str())) {
		// 查询失败
        cout << "error";
		return "";
	}
	MYSQL_RES *res = mysql_store_result(sql);
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) {
			result = row[0];
		}
		mysql_free_result(res);
	}
	return result; 
	}else if(index==1){
        //查询座位情况
		string ret = "";
        ret+=to_string((int)position);
        ret+="|";
        ret+=to_string((int)value1);
        ret+="|";
        ret+=value2;
        ret+="|";
        ret+=to_string((int)value3);
        return ret;
	} 
    return "";
} 

std::string joint_message(unsigned short lengths,int mess_id,char mess_type,std::string curs_message){
    std::stringstream ss;
    std::string temp = "";
    temp+=num_to_hex(GOAL,4);
    temp+=num_to_hex(lengths,4);
    temp+=num_to_hex(mess_id,8);
    temp+=num_to_hex(device_id,2);
    temp+=num_to_hex(mess_type,2);
    temp+=curs_message;
    temp+=num_to_hex(GOAL,4);
    return temp;
}

me split_message(std::string curs_message){//����
    if(curs_message.length()<24){
        me xx;
        xx.p = tran_type::MESSERROR;
        xx.message = "";
        return xx;
    }
    unsigned short goalh = hex_to_int(curs_message,0,4);
    if(goalh != 0xaa55){
        me xx;
        xx.p = tran_type::MESSERROR;
        xx.message = "";
        return xx;
    }
    unsigned short length = hex_to_int(curs_message,4,4);
    int mess_id = hex_to_int(curs_message,8,8);
    int cur_device_id = hex_to_int(curs_message,16,2);
    if(curs_message.length() != 24+length){
        me xx;
        xx.p = tran_type::MESSERROR;
        xx.message = "";
        return xx;
    }
    int mess_type = hex_to_int(curs_message,18,2);
    std::string cur_mess = curs_message.substr(20,length);
    unsigned short goale = hex_to_int(curs_message,20+length,4);
    // return cur_mess;
    me tmp;
    tmp.p = static_cast<tran_type>(mess_type);
    tmp.message = cur_mess;
    return tmp;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Base64 encode binary data
std::string base64_encode(const std::vector<unsigned char>& binary_data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    BIO_write(bio, binary_data.data(), static_cast<int>(binary_data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

// Base64 decode to binary data
std::vector<unsigned char> base64_decode(const std::string& base64_data) {
    BIO *bio, *b64;
    size_t decodeLen = base64_data.size();
    std::vector<unsigned char> result(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64_data.data(), static_cast<int>(base64_data.size()));
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines

    int actualLen = BIO_read(bio, result.data(), static_cast<int>(base64_data.size()));
    result.resize(actualLen);
    
    BIO_free_all(bio);

    return result;
}


std::string aes_encrypt(const std::vector<unsigned char>& plaintext, 
                                      const std::vector<unsigned char>& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL)) {
        handleErrors();
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
	handleErrors();
    }
    ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
	    handleErrors();
	}
    ciphertext_len += len;

	ciphertext.resize(ciphertext_len);
	EVP_CIPHER_CTX_free(ctx);
	std::string base64_ciphertext = base64_encode(ciphertext);
	return base64_ciphertext;
}

std::string aes_decrypt(const std::string& pre_ciphertext,
                                       const std::vector<unsigned char>& key) {
    std::vector<unsigned char> ciphertext = base64_decode(pre_ciphertext);
    std::cout<<pre_ciphertext<<std::endl;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL)) {
        handleErrors();
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
	std::string decrypted_str(plaintext.begin(), plaintext.end());
    return decrypted_str;
}

void init_ssl(){
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
} 

std::vector<unsigned char> string_to_vector(std::string keys){
	std::vector<unsigned char> ret;
	for(int i = 0;i<keys.length();++i)
		ret.push_back(keys[i]);
	return ret;	
}

void solve_mess(std::string mess,int client_socket){
    me tmp = split_message(mess);
    if(tmp.p == tran_type::REQUC){
		keys = tmp.message;
        cout << keys << endl;
		return ;
	}
    if(tmp.p == tran_type::MESSERROR){
        return ;
    }
    // cout << tmp.message << endl;
    tmp.message = aes_decrypt(tmp.message, string_to_vector(keys));
    // cout << (char)tmp.p <<" ";
    cout <<tmp.message<<" ";
    if(tmp.p == tran_type::REQUC_LOAD){
        //�����¼ 
        cout <<"REQUC_LOAD"<<endl;
		int index = tmp.message.find('|');
		std::string id = tmp.message.substr(0,index);
        std::string password = tmp.message.substr(index+1,tmp.message.length()-index-1);
        //获取数据库中id 为 id 的password
    // 获取数据库中id为id的密码
        cout <<"XXXXXX"<<endl;
        std::string db_password = sql_get(0, id); // 假设index=0表示获取密码
    if (db_password.empty()) {
        // 用户不存在
        cout<<"REQUC_LOAD_FAIL_NOUSER"<<endl;
        std::string ret = joint_message(0, 0, (char)tran_type::REQUC_LOAD_FAIL_NOUSER, "");
        send(client_socket, ret.c_str(), ret.size(), 0);
        return;
    }
    if (db_password == password) {
        // 密码正确
        cout <<"REQUC_LOAD_SUCCESS"<<endl;
        std::string ret = joint_message(0, 0, (char)tran_type::REQUC_LOAD_SUCCESS, "");
        send(client_socket, ret.c_str(), ret.size(), 0);
    } else {
        // 密码错误
        cout <<"REQUC_LOAD_FAIL_PWDERR"<<endl;
        std::string ret = joint_message(0, 0, (char)tran_type::REQUC_LOAD_FAIL_PWDERR, "");
        send(client_socket, ret.c_str(), ret.size(), 0);
    }
        
    }else if(tmp.p==tran_type::SMSREQUC){
        //��Կ���óɹ�
        //收到ID
        cout <<"SMSREQUC"<<endl;
        string id = tmp.message;
        code= generateRandomNumberString(6) ;
        send_sms(id,code);

    }else if(tmp.p==tran_type::PASSWORDSET){
        cout <<"PASSWORDSET"<<endl;
        int index1 = tmp.message.find('|');
        std::string id = tmp.message.substr(0,index1);
        int index2 = tmp.message.find('|',index1+1);
        std::string cur_code = tmp.message.substr(index1+1,index2-index1-1);
        std::string password = tmp.message.substr(index2+1,tmp.message.length()-index2-1);
        cout << cur_code<<" " <<code;
        if(cur_code==code){
            cout <<"XXXXX"<<endl;
            sql_insert_password(id,password);
        }else{
            string text = joint_message(0,0,(char)tran_type::SMSREQUC_FAIL,"");
            send(client_socket,text.c_str(),text.size(),0);
            return ;
        }
        string ret = joint_message(0,0,(char)tran_type::PASSWORDPASS,"");
        send(client_socket, ret.c_str(), ret.size(), 0);
    }else if(tmp.p==tran_type::QRCODE_UPLOAD){
        cout <<"QRCODE_UPLOAD"<<endl;
        string cur_id = tmp.message;
                if(sed.find(tmp.message)!= sed.end()){
                cout <<"alredy entry!!!"<<endl;
            }else{
                sed.insert(tmp.message);
                cout <<"entry success!!!"<<endl;
                value3 = que.front();
                que.pop();
                position += 1;
            }
    }else if(tmp.p==tran_type::CONNECTING) {
        if(tmp.message == "REQUC_DATA"){
        string text = sql_get(1,"");
        //加密解密
        string ret = joint_message(text.size(),0,(char)tran_type::CONNECTING,text);
        send(client_socket,ret.c_str(),ret.size(),0);
        cout << ret << " ";
    	cout <<"CONNECTING"<<endl;
        }else{
            if(se.find(tmp.message)!= se.end()){
                cout <<"alredy exist!!!"<<endl;
            }else{
                se.insert(tmp.message);
                cout <<"insert success"<<endl;
                value1 -= 1;
            }
        }
	}else{
        cout <<"OTHERSXXX"<<endl;
    }
}

// �����ͻ������ӵĺ���
void handle_client(int client_socket) {
    const int BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];

    // ��ȡ�ͻ��˷��͵�����
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            // �ͻ��˶Ͽ�����
            std::cout << "Client disconnected." << std::endl;
            break;
        }
		
        // ������յ�������
        std::cout << "Received from client: " <<client_socket<<" :"<< buffer << std::endl;
		solve_mess(std::string(buffer),client_socket);
        // ظͻ
        std::string response = "Server received: " + std::string(buffer);
        send(client_socket, response.c_str(), response.size(), 0);
    }

    // �رտͻ����׽���
    close(client_socket);
}

int main() {

    position = 0;
    value1 = 12;
    for(char i=1; i<=12; ++i) que.push(i);
	const char* host = "localhost"; //������
    const char* user = "root"; //�û���
    const char* pwd = "13579Acd"; //����
    const char* dbName = "cyh"; //���ݿ�����
    int port = 3306; //�˿ں�

    // ����mysql����
    sql = nullptr;
    sql = mysql_init(sql);
    if (!sql) {
        std::cout << "MySql init error!" << endl;
    }
    
    sql = mysql_real_connect(sql, host, user, pwd, dbName, port, nullptr, 0);
    if (!sql) {
        cout << "MySql Connect error!" << endl;
    }
	
    const int PORT = 8080;
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // �����׽���
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        return -1;
    }

    // ���÷�������ַ
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // ���׽���
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Failed to bind socket." << std::endl;
        close(server_socket);
        return -1;
    }

    // ��������
    if (listen(server_socket, 20) == -1) {
        std::cerr << "Failed to listen on socket." << std::endl;
        close(server_socket);
        return -1;
    }

    std::cout << "Server is listening on port " << PORT << "..." << std::endl;

    while (true) {
        // ���ܿͻ�������
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_socket == -1) {
            std::cerr << "Failed to accept connection." << std::endl;
            continue;
        }

        std::cout << "Client connected." << std::endl;

        // Ϊÿ���ͻ��˴���һ���߳�
        std::thread client_thread(handle_client, client_socket);
        client_thread.detach(); // �����̣߳�������������
    }

    // �رշ������׽���
    close(server_socket);
    return 0;
}
