
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
