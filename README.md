**KH5062CEM**

**PROGRAMMING AND ALGORITHMS**

**COURSEWORK 1**

![A picture containing graphical user interface Description
automatically
generated](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image1.png){width="2.995138888888889in"
height="0.7763888888888889in"}

Mahmoud Hegazy

CU2101083

March 23, 2024

DR SHAIMAA MUSAAD

ENG SHEREEN EL BOHY

# Contents {#contents .TOC-Heading}

[1. Introduction [3](#introduction)](#introduction)

[2. Instructions for Using the Application
[3](#instructions-for-using-the-application)](#instructions-for-using-the-application)

[2.1 Getting Started [3](#getting-started)](#getting-started)

[2.2 User Operations [3](#user-operations)](#user-operations)

[2.3 Password Management
[3](#password-management)](#password-management)

[2.4 Exiting [3](#exiting)](#exiting)

[3. Table of Unit Tests [4](#table-of-unit-tests)](#table-of-unit-tests)

[4. Repository Link [5](#repository-link)](#repository-link)

[5. Description of Algorithms
[5](#description-of-algorithms)](#description-of-algorithms)

[5.1 Hashing Algorithm (SHA-256)
[5](#hashing-algorithm-sha-256)](#hashing-algorithm-sha-256)

[5. 2 Encryption/Decryption (AES-256-CBC)
[5](#encryptiondecryption-aes-256-cbc)](#encryptiondecryption-aes-256-cbc)

[5.3 Hash Table for Storing Passwords (Using Open Addressing with Linear
Probing)
[5](#hash-table-for-storing-passwords-using-open-addressing-with-linear-probing)](#hash-table-for-storing-passwords-using-open-addressing-with-linear-probing)

[6. Methods and Functions Detail
[6](#methods-and-functions-detail)](#methods-and-functions-detail)

[6.1 Utility Functions [6](#utility-functions)](#utility-functions)

[6.2 Cryptography Functions
[6](#cryptography-functions)](#cryptography-functions)

[6.3 Password Hashing [7](#password-hashing)](#password-hashing)

[6.4 Random Password Generation
[7](#random-password-generation)](#random-password-generation)

[6.5 Class Methods [8](#class-methods)](#class-methods)

[6.5.1 Class User [8](#class-user)](#class-user)

[6.5.2 Class HashTable [8](#class-hashtable)](#class-hashtable)

[6.6 Supporting Methods [10](#supporting-methods)](#supporting-methods)

[7. Source Code [10](#source-code)](#source-code)

# 1. Introduction

The Password Manager Program is a straightforward, console-based tool
designed to help users keep their passwords safe and organized. Users
can easily create an account, sign in, and manage passwords for various
online services. Security is a top priority for this application, which
uses strong encryption to keep stored passwords safe and applies hashing
to protect user login details. With AES-256-CBC for encryption and
SHA-256 for hashing, the program ensures that sensitive information is
well protected from unauthorized access. This makes it a reliable and
secure choice for anyone looking to manage their passwords effectively.

# 2. Instructions for Using the Application

## 2.1 Getting Started

Compile the Program: Use a C++ compiler that supports C++17 or later,
ensuring that OpenSSL libraries are linked. Ex:

g++ -std=c++17 -o password_manager password_manager.cpp -l crypto -l ssl
-l pthread

Run the Program: Launch the compiled executable to start the
application. Ex:

./password_manager

## 2.2 User Operations

Sign Up: Choose the sign-up option and provide your name, email, and a
secure password.

Login: Select the login option and enter your email and password.

## 2.3 Password Management

Adding a Password: Once logged in, select the option to add a new
password, provide a label, and either choose to generate a random
password or enter your own.

Viewing Passwords: You can display a specific password by label or view
all stored passwords, which will be decrypted for display.

Deleting a Password: Select the delete option and provide the label of
the password you wish to remove.

## 2.4 Exiting

Logout: To exit, select the logout option.

# 3. Table of Unit Tests

  --------------------------------------------------------------------------------------------------------------------------------------------------
  Test   Description    Input          Expected       Actual Output
  Case                                 Output         
  ID                                                  
  ------ -------------- -------------- -------------- ----------------------------------------------------------------------------------------------
  TC1    Sign up with   Name, Email,   Success        ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image2.png){width="2.3229451006124235in"
         valid details  Password       message, user  height="0.8614260717410324in"}
                                       file created   

  TC2    Login with     Email,         Login success  ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image3.png){width="2.0903619860017497in"
         correct        Password       message        height="1.2274529746281715in"}
         credentials                                  

  TC3    Login with     Email,         Failure        ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image4.png){width="2.4478324584426945in"
         incorrect      Incorrect      message        height="0.8760662729658792in"}
         password       Password                      

  TC4    Add a new      Label,         Password added ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image5.png){width="2.4836800087489066in"
         password       Password       success        height="1.2030325896762906in"}
                                       message        

  TC5    Retrieve an    Label of       Display        ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image6.png){width="2.3546489501312338in"
         existing       existing       decrypted      height="1.2285126859142608in"}
         password       password       password       

  TC6    Delete an      Label of       Password       ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image7.png){width="2.1464873140857392in"
         existing       existing       deletion       height="1.12416447944007in"}
         password       password       success        
                                       message        

  TC7    Attempt to     Non-existent   No password    ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image8.png){width="2.2774825021872265in"
         retrieve a     label          found message  height="1.1162521872265967in"}
         non-existent                                 
         password                                     

  TC8    Logout and     Logout option  Logout         ![](vertopal_02ff4434d0f042f78aabd28c53e016b2/media/image9.png){width="2.0770002187226595in"
         exit the       selected       message,       height="1.446288276465442in"}
         application                   application    
                                       exits          
  --------------------------------------------------------------------------------------------------------------------------------------------------

# 4. Repository Link

[Hegazy's Password
Manager](https://github.com/Mhegazyy/Password-Manager)

# 5. Description of Algorithms

## 5.1 Hashing Algorithm (SHA-256)

-   **Purpose:** Securely hash user passwords for storage, ensuring that
    actual passwords are not stored in the system, thus enhancing
    security by protecting against password theft.

-   **Complexity:** *O*(*n*) - The time complexity is linear relative to
    the size of the input password. This is because the algorithm
    processes each character of the input password once.

## 5. 2 Encryption/Decryption (AES-256-CBC)

-   **Purpose:** Encrypt user passwords before storage and decrypt them
    for display to the user. This process ensures that even if the data
    is accessed by unauthorized individuals, the passwords remain
    protected.

-   **Complexity:** *O*(*n*) - Both encryption and decryption processes
    have a time complexity proportional to the length of the password.
    This linear complexity arises from processing each block of the
    plaintext or ciphertext.

## 5.3 Hash Table for Storing Passwords (Using Open Addressing with Linear Probing)

-   **Purpose:** Efficiently store and retrieve passwords using labels
    as keys. Open addressing with linear probing is a collision
    resolution method that places all entries directly in the hash table
    array, probing for the next open slot in case of collisions.

-   **Complexity:**

    -   **Average Case:** *O*(1) for insert, delete, and search
        operations under the assumption of low to moderate load factors.
        This ideal performance is due to direct indexing and minimal
        probing under optimal conditions.

    -   **Worst Case:** *O*(*n*) when many entries hash to the same
        index or close indices, leading to extended probing sequences.
        This scenario can happen with a high load factor or poor hash
        function distribution.

# 6. Methods and Functions Detail

In the context of the Password Manager application, several key methods
and functions facilitate the core functionalities of user management,
password encryption/decryption, and secure storage. Below is a detailed
overview of these components:

## 6.1 Utility Functions

-   **bin2hex(const unsigned char\* bin, size_t len)**

    -   **Purpose:** Converts binary data into a hexadecimal string.
        This is particularly useful for representing encrypted data as a
        string that can be stored or displayed.

    -   **Parameters:**

        -   **bin**: Pointer to the binary data array.

        -   **len**: Length of the binary data array.

    -   **Return Value:** A **string** representing the hexadecimal
        value of the binary input.

-   **hex2bin(const string& hex, vector\<unsigned char\>& bin)**

    -   **Purpose:** Converts a hexadecimal string back into binary
        data, which is necessary for decryption processes that require
        binary data as input.

    -   **Parameters:**

        -   **hex**: The hexadecimal string to be converted.

        -   **bin**: A reference to a vector of unsigned chars that will
            store the binary output.

    -   **Return Value:** A **bool** indicating whether the conversion
        was successful. This is important to check as the hex string
        needs to have an even length and valid hex characters.

## 6.2 Cryptography Functions

-   **encrypt(const unsigned char\* plaintext, int plaintext_len,
    unsigned char\* key, unsigned char\* iv, unsigned char\* ciphertext,
    int& ciphertext_len)**

    -   **Purpose:** Encrypts plaintext using AES-256-CBC, ensuring
        secure storage of user passwords.

    -   **Parameters:**

        -   **plaintext**: Pointer to the plaintext data array.

        -   **plaintext_len**: Length of the plaintext data.

        -   **key**: Encryption key (must be 32 bytes for AES-256).

        -   **iv**: Initialization vector for the cipher.

        -   **ciphertext**: Buffer to hold the encrypted data.

        -   **ciphertext_len**: Reference to an int that will be updated
            with the length of the ciphertext.

    -   **Return Value:** **bool** indicating success of the encryption
        operation. This is crucial for validating that encryption was
        performed correctly before storage.

-   **decrypt(const unsigned char\* ciphertext, int ciphertext_len,
    unsigned char\* key, unsigned char\* iv, unsigned char\* plaintext,
    int& plaintext_len)**

    -   **Purpose:** Decrypts ciphertext back into plaintext, allowing
        users to retrieve their stored passwords.

    -   **Parameters:** Mirrors the **encrypt** function, but operates
        in reverse, converting ciphertext back into plaintext.

    -   **Return Value:** **bool** indicating the success of the
        decryption operation. Successful decryption is key to ensuring
        that users can access their stored information.

## 6.3 Password Hashing

-   **hashPassword(const string& password)**

    -   **Purpose:** Hashes a password using SHA-256, which is a one-way
        operation that securely stores user login passwords.

    -   **Parameters:**

        -   **password**: The user\'s plaintext password.

    -   **Return Value:** A **string** representing the hexadecimal hash
        of the password. This hashed value is used for secure storage
        and verification of user passwords without needing to store the
        actual password.

## 6.4 Random Password Generation

-   **generateRandomPassword()**

    -   **Purpose:** Generates a secure, random password for users who
        prefer not to create their own.

    -   **Parameters:** None.

    -   **Return Value:** A **string** containing the newly generated
        password. This method ensures that users have the option to use
        a strong, random password for their accounts or services.

## 6.5 Class Methods

### 6.5.1 Class User

-   **loadPasswords()**

    -   **Purpose:** Loads the user\'s encrypted passwords from a file
        into the hash table for use during the session.

    -   **Parameters:** None.

    -   **Return Value:** **bool** indicating success of loading the
        passwords. This is important for error checking and ensuring the
        user\'s passwords are available for management.

-   **savePasswords()**

    -   **Purpose:** Saves all of the user\'s passwords, which are
        stored in the hash table, back into a file. Passwords are
        encrypted before storage.

    -   **Parameters:** None.

    -   **Return Value:** None directly, but it updates the file
        associated with the user. Ensuring data persistence across
        sessions.

-   **displayAll()**

    -   **Purpose:** Decrypts and displays all stored passwords for the
        user.

    -   **Parameters:** None.

    -   **Return Value:** None directly, but outputs the label and
        decrypted password for each entry stored by the user. This
        function is crucial for user password management.

### 6.5.2 Class HashTable

-   **put(const string& key, const string& value)**

    -   **Purpose:** Inserts a new key-value pair into the hash table
        using open addressing and linear probing to resolve collisions
        or updates the value if the key already exists. Efficient
        management of password storage is ensured by adding new entries
        or updating existing ones without using additional data
        structures like linked lists.

    -   **Parameters:**

        -   **key**: The label for the password.

        -   **value**: The encrypted password.

    -   **Return Value:** None directly. This method modifies the hash
        table by inserting a new entry or updating an existing one.
        It\'s critical for efficient password storage and retrieval.

-   **get(const string& key)**

    -   **Purpose:** Retrieves the value associated with a given key in
        the hash table by linearly probing through occupied slots. This
        method enables the decryption and display of stored passwords by
        finding the correct slot even in the presence of collisions.

    -   **Parameters:**

        -   **key**: The label for which the password is to be
            retrieved.

    -   **Return Value:** A string that represents the encrypted
        password associated with the given label. If the key does not
        exist or has been marked as deleted, an empty string is
        returned, signaling the absence of that particular password.

-   **remove(const string& key)**

    -   **Purpose:** Removes a key-value pair from the hash table based
        on the provided key. This is achieved by marking the entry as
        logically deleted without physically removing it, thus
        maintaining the integrity of the probe sequence for other
        entries.

    -   **Parameters:**

        -   **key**: The label of the password to be removed.

    -   **Return Value:** A bool indicating whether the removal was
        successful. This method informs the user whether the specified
        password has been successfully marked as deleted, ensuring that
        the space can be reused for new entries.

-   **forEachEntry(function\<void(const string&, const string&)\>
    func)**

    -   **Purpose:** Iterates over each entry in the hash table,
        executing a provided function for each occupied (and not
        logically deleted) entry. This allows for operations such as
        displaying all passwords, performing batch updates, or deletions
        across the hash table entries.

    -   **Parameters:**

        -   **func**: A function that takes two strings (key and value)
            and performs an operation with them. This flexible mechanism
            allows for direct manipulation or display of the hash table
            contents.

    -   **Return Value:** None directly. This method facilitates actions
        on all active hash table entries, enabling operations like
        printing all stored passwords or modifying them in bulk.

## 6.6 Supporting Methods

-   **hash(const string& key) (Private within HashTable class)**

    -   **Purpose:** Generates a hash value for the given key. This hash
        value determines the index in the table where the key-value pair
        will be stored.

    -   **Parameters:**

        -   **key**: The string for which the hash is to be generated.

    -   **Return Value:** A **size_t** value representing the calculated
        hash. This method ensures that the hash table can efficiently
        store and retrieve data based on the key.

# 7. Source Code

*#include* \<iostream\>

*#include* \<fstream\>

*#include* \<ctime\>

*#include* \<string\>

*#include* \<functional\>

*#include* \<filesystem\>

*#include* \<openssl/evp.h\>

*#include* \<openssl/err.h\>

*#include* \<iomanip\>

*#include* \<sstream\>

*using* *namespace* std;

const string userDataFolder *=* \"./UserData\";

struct PasswordEntry {

    string label;

    string password;

};

string bin2hex(const unsigned char\* bin, size_t len) {

    stringstream ss;

    ss *\<\<* hex *\<\<* setfill(\'0\');

    *for* (int i *=* 0; i *\<* len; *++*i) {

        ss *\<\<* setw(2) *\<\<* (int)bin\[i\];

    }

    *return* ss.str();

}

bool hex2bin(const string& hex, vector\<unsigned char\>& bin) {

    size_t len *=* hex.length();

    *if* (len *&* 1) *return* false; *// Hex string must be even size*

    bin.clear();

    bin.reserve(len */* 2);

    *for* (size_t i *=* 0; i *\<* len; i *+=* 2) {

        unsigned int byte;

        istringstream iss(hex.substr(i, 2));

        *if* (*!*(iss *\>\>* std::hex *\>\>* byte)) *return* false;

        bin.push_back(*static_cast\<*unsigned char*\>*(byte));

    }

    *return* true;

}

bool encrypt(const unsigned char\* plaintext, int plaintext_len,
unsigned char\* key,

    unsigned char\* iv, unsigned char\* ciphertext, int& ciphertext_len)
{

    EVP_CIPHER_CTX*\** ctx;

    int len;

    int final_len;

*    // Create and initialize the context*

    *if* (*!*(ctx *=* EVP_CIPHER_CTX_new())) *return* false;

*    // Initialize the encryption operation with AES-256-CBC*

    *if* (1 *!=* EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key,
iv)) *return* false;

*    // Provide the plaintext to be encrypted*

    *if* (1 *!=* EVP_EncryptUpdate(ctx, ciphertext, *&*len, plaintext,
plaintext_len)) *return* false;

    ciphertext_len *=* len;

*    // Finalize the encryption*

    *if* (1 *!=* EVP_EncryptFinal_ex(ctx, ciphertext *+* len, *&*len))
*return* false;

    ciphertext_len *+=* len;

*    // Clean up*

    EVP_CIPHER_CTX_free(ctx);

    *return* true;

}

bool decrypt(const unsigned char\* ciphertext, int ciphertext_len,
unsigned char\* key,

    unsigned char\* iv, unsigned char\* plaintext, int& plaintext_len) {

    EVP_CIPHER_CTX*\** ctx;

    int len;

    int final_len;

*    // Create and initialize the context*

    *if* (*!*(ctx *=* EVP_CIPHER_CTX_new())) *return* false;

*    // Initialize the decryption operation with AES-256-CBC*

    *if* (1 *!=* EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key,
iv)) *return* false;

*    // Provide the ciphertext to be decrypted*

    *if* (1 *!=* EVP_DecryptUpdate(ctx, plaintext, *&*len, ciphertext,
ciphertext_len)) *return* false;

    plaintext_len *=* len;

*    // Finalize the decryption*

    *if* (1 *!=* EVP_DecryptFinal_ex(ctx, plaintext *+* len, *&*len))
*return* false;

    plaintext_len *+=* len;

*    // Clean up*

    EVP_CIPHER_CTX_free(ctx);

    *return* true;

}

class HashTable {

public:

    struct Node {

        string key;

        string value;

        bool occupied *=* false; *// Indicates if the slot is occupied*

        bool isDeleted *=* false; *// Indicates if the slot has been
logically deleted*

        Node() : key(\"\"), value(\"\"), occupied(false),
isDeleted(false) {}

    };

private:

    vector*\<*Node*\>* table;

    size_t num_elements;

    static const size_t default_size *=* 50; *// Default size of the
hash table*

    size_t hash(const string& key) const {

        size_t hashValue *=* 0;

        *for* (char c : key) {

            hashValue *=* (hashValue *\** 31 *+* c) *%* table.size();

        }

        *return* hashValue;

    }

public:

    HashTable(size_t size *=* default_size) : table(size),
num_elements(0) {}

    void put(const string& key, const string& value) {

        size_t index *=* hash(key);

        *while* (table\[index\].occupied *&&* table\[index\].key *!=*
key) {

            index *=* (index *+* 1) *%* table.size();

        }

        *if* (*!*table\[index\].occupied *\|\|*
table\[index\].isDeleted) {

            table\[index\].key *=* key;

            table\[index\].value *=* value;

            table\[index\].occupied *=* true;

            table\[index\].isDeleted *=* false;

            *++*num_elements;

        }

        *else* *if* (table\[index\].key *==* key) {

*            // Update existing value*

            table\[index\].value *=* value;

        }

    }

    string get(const string& key) {

        size_t index *=* hash(key);

        size_t start *=* index;

        *while* (table\[index\].occupied *\|\|*
table\[index\].isDeleted) {

            *if* (table\[index\].occupied *&&* table\[index\].key *==*
key) {

                *return* table\[index\].value;

            }

            index *=* (index *+* 1) *%* table.size();

            *if* (index *==* start) *break*; *// Avoid infinite loop*

        }

        *return* \"\"; *// Key not found*

    }

    bool remove(const string& key) {

        size_t index *=* hash(key);

        size_t start *=* index;

        *while* (table\[index\].occupied *\|\|*
table\[index\].isDeleted) {

            *if* (table\[index\].occupied *&&* table\[index\].key *==*
key *&&* *!*table\[index\].isDeleted) {

                table\[index\].isDeleted *=* true; *// Mark as deleted*

                *\--*num_elements;

                *return* true;

            }

            index *=* (index *+* 1) *%* table.size();

            *if* (index *==* start) *break*; *// Avoid infinite loop*

        }

        *return* false; *// Key not found*

    }

    void forEachEntry(function\<void(const string*&*, const string*&*)\>
func) const {

        *for* (const auto*&* node : table) {

            *if* (node.occupied *&&* *!*node.isDeleted) {

                func(node.key, node.value);

            }

        }

    }

};

class User {

public:

    string name;

    string email;

    string passwordHash;

    HashTable passwords;

    User() : passwords(50) {} *// Initialize HashTable with a default
size*

    bool loadPasswords() {

        ifstream file(filesystem::path(userDataFolder) */* (email *+*
\".txt\"));

        *if* (*!*file) {

            cout *\<\<* \"No password file found.\\n\";

            *return* false;

        }

        string temp;

        getline(file, temp);

        getline(file, temp);

        string label, password;

        *while* (file *\>\>* label *\>\>* password) {

            passwords.put(label, password);

        }

        *return* true;

    }

    void savePasswords() {

        ofstream file(filesystem::path(userDataFolder) */* (email *+*
\".txt\"));

        *if* (file) {

*            // Write the user\'s email and hashed password on the first
two lines*

            file *\<\<* email *\<\<* \"\\n\" *\<\<* passwordHash *\<\<*
\"\\n\";

*            // Then, for each entry in the hash table, write the label
and encrypted password*

            passwords.forEachEntry(\[*&*file\](const string& label,
const string& encryptedPassword) {

                file *\<\<* label *\<\<* \" \" *\<\<* encryptedPassword
*\<\<* endl;

                });

        }

        *else* {

            cerr *\<\<* \"Failed to open file for writing.\\n\";

        }

    }

    void displayAll() {

        unsigned char key\[32\] *=* { *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35, *0x*36, *0x*37,

                                 *0x*38, *0x*39, *0x*30, *0x*31, *0x*32,
*0x*33, *0x*34, *0x*35,

                                 *0x*36, *0x*37, *0x*38, *0x*39, *0x*30,
*0x*31, *0x*32, *0x*33,

                                 *0x*34, *0x*35, *0x*36, *0x*37, *0x*38,
*0x*39, *0x*30, *0x*31 };

        unsigned char iv\[16\] *=* { *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35, *0x*36, *0x*37,

                                *0x*38, *0x*39, *0x*30, *0x*31, *0x*32,
*0x*33, *0x*34, *0x*35 };

        passwords.forEachEntry(\[*&*\](const string& label, const
string& encryptedPasswordHex) {

            unsigned char decryptedPassword\[1024\]; *// Ensure this
buffer is large enough*

            int decryptedPassword_len;

*            // Convert hex string to binary for decryption*

            vector*\<*unsigned char*\>* ciphertext;

            *if* (*!*hex2bin(encryptedPasswordHex, ciphertext)) {

                cout *\<\<* \"Error converting hex to binary for label:
\" *\<\<* label *\<\<* endl;

                *return*; *// Continue to next entry*

            }

*            // Decrypt the password*

            *if* (decrypt(ciphertext.data(), ciphertext.size(), key, iv,
decryptedPassword, decryptedPassword_len)) {

*                // Ensure null-termination of the decrypted password*

                decryptedPassword\[decryptedPassword_len\] *=* \'\\0\';

*                // Display label and decrypted password*

                cout *\<\<* \"Label: \" *\<\<* label *\<\<*
\"\\nPassword: \" *\<\<* decryptedPassword *\<\<* endl;

            }

            *else* {

                cerr *\<\<* \"Decryption failed for label: \" *\<\<*
label *\<\<* endl;

            }

            });

    }

};

string hashPassword(const string& password) {

*    // Create a buffer to hold the hash*

    unsigned char hash\[EVP_MAX_MD_SIZE\];

    unsigned int lengthOfHash *=* 0;

*    // Create a \'message digest context\' to hold the operation\'s
state*

    EVP_MD_CTX*\** mdctx *=* EVP_MD_CTX_new();

    *if* (mdctx *==* nullptr) {

        cerr *\<\<* \"Failed to create EVP_MD_CTX\" *\<\<* endl;

        *return* \"\";

    }

*    // Initialize the digest operation, select the SHA256 algorithm*

    *if* (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) *!=* 1) {

        cerr *\<\<* \"Failed to initialize digest operation\" *\<\<*
endl;

        EVP_MD_CTX_free(mdctx);

        *return* \"\";

    }

*    // Provide the message to be digested*

    *if* (EVP_DigestUpdate(mdctx, password.c_str(), password.size())
*!=* 1) {

        cerr *\<\<* \"Failed to provide data to digest operation\"
*\<\<* endl;

        EVP_MD_CTX_free(mdctx);

        *return* \"\";

    }

*    // Retrieve the digest*

    *if* (EVP_DigestFinal_ex(mdctx, hash, *&*lengthOfHash) *!=* 1) {

        cerr *\<\<* \"Failed to finalize digest operation\" *\<\<* endl;

        EVP_MD_CTX_free(mdctx);

        *return* \"\";

    }

*    // Clean up*

    EVP_MD_CTX_free(mdctx);

*    // Convert the hash to a hex string*

    stringstream ss;

    *for* (unsigned int i *=* 0; i *\<* lengthOfHash; i*++*) {

        ss *\<\<* hex *\<\<* setw(2) *\<\<* setfill(\'0\') *\<\<*
(int)hash\[i\];

    }

    *return* ss.str();

}

void newUser(User& user) {

    create_directories(filesystem::path(userDataFolder)); *// Ensure the
folder exists*

    cout *\<\<* \"Enter your name: \";

    getline(cin, user.name);

    cout *\<\<* \"Enter your email: \";

    getline(cin, user.email);

    cout *\<\<* \"Set your password: \";

    getline(cin, user.passwordHash);

    string hashedPassword *=* hashPassword(user.passwordHash); *// Hash
the user\'s password*

*    // Open the file for this user in the folder*

    ofstream file(filesystem::path(userDataFolder) */* (user.email *+*
\".txt\"));

    *if* (*!*file.is_open()) {

        cerr *\<\<* \"Error creating file for user.\\n\";

        *return*;

    }

*    // Write the email, hashed password, and name*

    file *\<\<* user.email *\<\<* \"\\n\" *\<\<* hashedPassword *\<\<*
endl;

    cout *\<\<* \"Thank you for signing up with us, \" *\<\<* user.name
*\<\<* \"!\\n\";

}

bool verifyUser(const string& email, const string& inputPassword, User&
user) {

    filesystem::path filePath *=* filesystem::path(userDataFolder) */*
(email *+* \".txt\");

    ifstream file(filePath);

    *if* (*!*file) {

        cout *\<\<* \"User not found.\\n\";

        *return* false;

    }

*    // Directly read the email and hashed password*

    string storedEmail, storedHashedPassword, name;

    getline(file, storedEmail); *// Read stored email (first line)*

    getline(file, storedHashedPassword); *// Read stored hashed password
(second line)*

*    // Compare hashed values*

    *if* (hashPassword(inputPassword) *==* storedHashedPassword) {

*        // Assuming User has a constructor or method to initialize it
properly*

        user.email *=* email;

        user.passwordHash *=* storedHashedPassword; *// To add to user
file incase of password deletion*

        user.name *=* name; *// Assign the read name to the user object*

        cout *\<\<* \"Login successful. Welcome back, \" *\<\<* name
*\<\<* \"!\\n\";

*        // Proceed with showing the user menu or further actions*

        *return* true;

    }

    *else* {

        cout *\<\<* \"Invalid password.\\n\";

        *return* false;

    }

}

string generateRandomPassword() {

    string chars *=*

        \"0123456789\"

        \"ABCDEFGHIJKLMNOPQRSTUVWXYZ\"

        \"abcdefghijklmnopqrstuvwxyz\"

        \"!@#\$%\^&\*()\";

    string password;

    srand(*static_cast\<*unsigned*\>*(time(nullptr)));

    int length *=* rand() *%* 5 *+* 8; *// Length between 8 and 12*

    *for* (int i *=* 0; i *\<* length; *++*i) {

        password *+=* chars\[rand() *%* chars.length()\];

    }

    *return* password;

}

void addUserPassword(User& user) {

    string label, passwordChoice, password;

    cout *\<\<* \"Please enter a label for your new password: \";

    getline(cin, label);

    cout *\<\<* \"Would you like to generate a new password? (yes/no):
\";

    getline(cin, passwordChoice);

    *if* (passwordChoice *==* \"yes\" *\|\|* passwordChoice *==*
\"Yes\") {

        password *=* generateRandomPassword();

        cout *\<\<* \"Generated Password: \" *\<\<* password *\<\<*
endl;

    }

    *else* {

        cout *\<\<* \"Enter your password: \";

        getline(cin, password);

    }

*    //Use Hexadecimal values to avoid usage of null terminator*

    unsigned char key\[32\] *=* { *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35, *0x*36, *0x*37,

                         *0x*38, *0x*39, *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35,

                         *0x*36, *0x*37, *0x*38, *0x*39, *0x*30, *0x*31,
*0x*32, *0x*33,

                         *0x*34, *0x*35, *0x*36, *0x*37, *0x*38, *0x*39,
*0x*30, *0x*31 };

    unsigned char iv\[16\] *=* { *0x*30, *0x*31, *0x*32, *0x*33, *0x*34,
*0x*35, *0x*36, *0x*37,

                        *0x*38, *0x*39, *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35 };

    unsigned char plaintext\[1024\]; *// Make sure this buffer is large
enough*

    strncpy_s((char*\**)plaintext, *sizeof*(plaintext),
password.c_str(), \_TRUNCATE);

*    // Ensure null termination*

    int plaintext_len *=* strlen((char*\**)plaintext);

    unsigned char ciphertext\[1024\]; *// Adjust size as needed*

    int ciphertext_len;

*    // Encrypt the password*

    *if* (encrypt(plaintext, plaintext_len, key, iv, ciphertext,
ciphertext_len)) {

*        // Convert binary ciphertext to hex string for storage*

        string encryptedPasswordHex *=* bin2hex(ciphertext,
ciphertext_len);

       

        user.passwords.put(label, encryptedPasswordHex); *//Adding
password to the hashtable*

*        //Adding password to user data file*

        ofstream file(filesystem::path(userDataFolder) */* (user.email
*+* \".txt\"), ios::app);

        *if* (*!*file) {

            cout *\<\<* \"Error updating file for user.\\n\";

            *return*;

        }

        file *\<\<* label *\<\<* \" \" *\<\<* encryptedPasswordHex
*\<\<* endl;

        cout *\<\<* \"Password added to your keychain.\\n\";

    }

    *else* {

        cerr *\<\<* \"Encryption failed.\\n\";

    }

}

*// Method to start the application engine*

void showMenu(User& user) {

    int choice;

    *do* {

        cout *\<\<*
\"\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--\\n\";

        cout *\<\<* \"What would you like to do?\\n\";

        cout *\<\<* \"1. Display a specific password by choosing a
label\\n\";

        cout *\<\<* \"2. Display all passwords\\n\";

        cout *\<\<* \"3. Add a new password\\n\";

        cout *\<\<* \"4. Delete a password\\n\";

        cout *\<\<* \"5. Log Out and Exit\\n\";

        cout *\<\<* \"Enter your choice: \";

        cin *\>\>* choice;

        cin.ignore(numeric_limits\<streamsize\>::max(), \'\\n\');

        cout *\<\<*
\"\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--\\n\";

        *switch* (choice) {

        *case* 1: {

            cout *\<\<* \"Available labels:\\n\";

            user.passwords.forEachEntry(\[\](const string& key, const
string& value) {

                cout *\<\<* \"- \" *\<\<* key *\<\<* endl; * // Display
key; ignore value*

                });

            cout *\<\<* \"Enter the label of the password you want to
display: \";

            string chosenLabel;

            getline(cin, chosenLabel);

            string encryptedPasswordHex *=*
user.passwords.get(chosenLabel);

            *if* (*!*encryptedPasswordHex.empty()) {

                vector*\<*unsigned char*\>* encryptedPasswordBin;

                *if* (hex2bin(encryptedPasswordHex,
encryptedPasswordBin)) {

                    unsigned char decryptedPassword\[1024\]; *// Ensure
this buffer is large enough*

                    int decryptedPasswordLen *=* 0;

*                    //Use Hexadecimal values to avoid usage of null
terminator*

                    unsigned char key\[32\] *=* { *0x*30, *0x*31,
*0x*32, *0x*33, *0x*34, *0x*35, *0x*36, *0x*37,

                         *0x*38, *0x*39, *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35,

                         *0x*36, *0x*37, *0x*38, *0x*39, *0x*30, *0x*31,
*0x*32, *0x*33,

                         *0x*34, *0x*35, *0x*36, *0x*37, *0x*38, *0x*39,
*0x*30, *0x*31 };

                    unsigned char iv\[16\] *=* { *0x*30, *0x*31, *0x*32,
*0x*33, *0x*34, *0x*35, *0x*36, *0x*37,

                        *0x*38, *0x*39, *0x*30, *0x*31, *0x*32, *0x*33,
*0x*34, *0x*35 };

*                    // Decrypt the password*

                    *if* (decrypt(encryptedPasswordBin.data(),
encryptedPasswordBin.size(), key, iv, decryptedPassword,
decryptedPasswordLen)) {

                        decryptedPassword\[decryptedPasswordLen\] *=*
\'\\0\'; *// Null-terminate the decrypted password*

                        cout *\<\<* \"Password for \" *\<\<* chosenLabel
*\<\<* \" is: \" *\<\<* decryptedPassword *\<\<* endl;

                    }

                    *else* {

                        cout *\<\<* \"Failed to decrypt password for \"
*\<\<* chosenLabel *\<\<* endl;

                    }

                }

                *else* {

                    cout *\<\<* \"Failed to convert encrypted password
to binary for \" *\<\<* chosenLabel *\<\<* endl;

                }

            }

            *else* {

                cout *\<\<* \"No password found for label: \" *\<\<*
chosenLabel *\<\<* endl;

            }

            *break*;

        }

        *case* 2:

            cout *\<\<* \"Stored passwords:\\n\";

            user.displayAll();

            *break*;

        *case* 3:

            addUserPassword(user);

            *break*;

        *case* 4: {

            cout *\<\<* \"Available labels:\\n\";

            user.passwords.forEachEntry(\[\](const string& key, const
string& value) {

                cout *\<\<* \"- \" *\<\<* key *\<\<* endl; * // Display
key; ignore value*

                });

            cout *\<\<* \"Enter the label of the password you want to
delete: \";

            string label;

            getline(cin, label);

            *if* (user.passwords.remove(label)) {

                cout *\<\<* \"Password deleted successfully.\\n\";

                user.savePasswords(); *// Save the updated list of
passwords to the file*

            }

            *else* {

                cout *\<\<* \"No password found for label: \" *\<\<*
label *\<\<* \".\\n\";

            }

            *break*;

        }

        *case* 5:

            cout *\<\<* \"Logging out\...\\n\";

            *break*;

        *default*:

            cout *\<\<* \"Invalid option. Please try again.\\n\";

        }

        cout *\<\<*
\"\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--\\n\";

    } *while* (choice *!=* 5);

}

int main() {

    int option;

    User user;

    bool isLoggedIn *=* false;

    cout *\<\<* \"Please choose an option: \\n1. Sign Up\\n2.
Login\\n\";

    cout *\<\<* \"Enter your choice: \";

    cin *\>\>* option;

    cin.ignore(numeric_limits\<streamsize\>::max(), \'\\n\'); *// Clear
the input buffer*

    *if* (option *==* 1) {

        User new_User;

        newUser(new_User);

        user *=* new_User;

        *if* (user.loadPasswords()) {

            isLoggedIn *=* true;

            cout *\<\<* \"Welcome, \" *\<\<* user.name *\<\<* \"! You
are now logged in.\\n\";

        }

    }

    *else* *if* (option *==* 2) {

        string email, password;

*        // Prompt for user login*

        cout *\<\<* \"Enter your email: \";

        getline(cin, email);

        cout *\<\<* \"Enter your password: \";

        getline(cin, password);

        *if* (verifyUser(email, password, user)) {

            isLoggedIn *=* true;

            user.loadPasswords();

            cout *\<\<* \"Welcome back, \" *\<\<* user.name *\<\<*
\"!\\n\";

        }

        *else* {

            cout *\<\<* \"Invalid login. Please check your email and
password.\\n\";

        }

    }

    *else* {

        cout *\<\<* \"Invalid option selected.\\n\";

    }

    *if* (isLoggedIn) {

        showMenu(user); *// Show the menu for the logged-in user.*

    }

    *return* 0;

}
