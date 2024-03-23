#include <iostream>
#include <fstream>
#include <ctime>
#include <string>
#include <functional>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>



using namespace std;

const string userDataFolder = "./UserData";

struct PasswordEntry {
    string label;
    string password;
};

string bin2hex(const unsigned char* bin, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; ++i) {
        ss << setw(2) << (int)bin[i];
    }
    return ss.str();
}

bool hex2bin(const string& hex, vector<unsigned char>& bin) {
    size_t len = hex.length();
    if (len & 1) return false; // Hex string must be even size
    bin.clear();
    bin.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        istringstream iss(hex.substr(i, 2));
        if (!(iss >> std::hex >> byte)) return false;
        bin.push_back(static_cast<unsigned char>(byte));
    }
    return true;
}


bool encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* iv, unsigned char* ciphertext, int& ciphertext_len) {
    EVP_CIPHER_CTX* ctx;

    int len;
    int final_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) return false;

    // Initialize the encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;

    // Provide the plaintext to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return false;
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return false;
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool decrypt(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* iv, unsigned char* plaintext, int& plaintext_len) {
    EVP_CIPHER_CTX* ctx;

    int len;
    int final_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) return false;

    // Initialize the decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) return false;

    // Provide the ciphertext to be decrypted
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return false;
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return false;
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}



class HashTable {
public:
    struct Node {
        string key;
        string value;
        bool occupied = false; // Indicates if the slot is occupied
        bool isDeleted = false; // Indicates if the slot has been logically deleted
        Node() : key(""), value(""), occupied(false), isDeleted(false) {}
    };

private:
    vector<Node> table;
    size_t num_elements;
    static const size_t default_size = 50; // Default size of the hash table

    size_t hash(const string& key) const {
        size_t hashValue = 0;
        for (char c : key) {
            hashValue = (hashValue * 31 + c) % table.size();
        }
        return hashValue;
    }

public:
    HashTable(size_t size = default_size) : table(size), num_elements(0) {}

    void put(const string& key, const string& value) {
        size_t index = hash(key);
        while (table[index].occupied && table[index].key != key) {
            index = (index + 1) % table.size();
        }
        if (!table[index].occupied || table[index].isDeleted) {
            table[index].key = key;
            table[index].value = value;
            table[index].occupied = true;
            table[index].isDeleted = false;
            ++num_elements;
        }
        else if (table[index].key == key) {
            // Update existing value
            table[index].value = value;
        }
    }

    string get(const string& key) {
        size_t index = hash(key);
        size_t start = index;
        while (table[index].occupied || table[index].isDeleted) {
            if (table[index].occupied && table[index].key == key) {
                return table[index].value;
            }
            index = (index + 1) % table.size();
            if (index == start) break; // Avoid infinite loop
        }
        return ""; // Key not found
    }

    bool remove(const string& key) {
        size_t index = hash(key);
        size_t start = index;
        while (table[index].occupied || table[index].isDeleted) {
            if (table[index].occupied && table[index].key == key && !table[index].isDeleted) {
                table[index].isDeleted = true; // Mark as deleted
                --num_elements;
                return true;
            }
            index = (index + 1) % table.size();
            if (index == start) break; // Avoid infinite loop
        }
        return false; // Key not found
    }

    void forEachEntry(function<void(const string&, const string&)> func) const {
        for (const auto& node : table) {
            if (node.occupied && !node.isDeleted) {
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

    User() : passwords(50) {} // Initialize HashTable with a default size

    bool loadPasswords() {
        ifstream file(filesystem::path(userDataFolder) / (email + ".txt"));
        if (!file) {
            cout << "No password file found.\n";
            return false;
        }
        string temp;
        getline(file, temp);
        getline(file, temp);

        string label, password;
        while (file >> label >> password) {
            passwords.put(label, password);
        }
        return true;
    }

    void savePasswords() {
        ofstream file(filesystem::path(userDataFolder) / (email + ".txt"));
        if (file) {
            // Write the user's email and hashed password on the first two lines
            file << email << "\n" << passwordHash << "\n";
            // Then, for each entry in the hash table, write the label and encrypted password
            passwords.forEachEntry([&file](const string& label, const string& encryptedPassword) {
                file << label << " " << encryptedPassword << endl;
                });
        }
        else {
            cerr << "Failed to open file for writing.\n";
        }
    }


    void displayAll() {
        unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                                 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31 };
        unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

        passwords.forEachEntry([&](const string& label, const string& encryptedPasswordHex) {
            unsigned char decryptedPassword[1024]; // Ensure this buffer is large enough
            int decryptedPassword_len;

            // Convert hex string to binary for decryption
            vector<unsigned char> ciphertext;
            if (!hex2bin(encryptedPasswordHex, ciphertext)) {
                cout << "Error converting hex to binary for label: " << label << endl;
                return; // Continue to next entry
            }

            // Decrypt the password
            if (decrypt(ciphertext.data(), ciphertext.size(), key, iv, decryptedPassword, decryptedPassword_len)) {
                // Ensure null-termination of the decrypted password
                decryptedPassword[decryptedPassword_len] = '\0';

                // Display label and decrypted password
                cout << "Label: " << label << "\nPassword: " << decryptedPassword << endl;
            }
            else {
                cerr << "Decryption failed for label: " << label << endl;
            }
            });
    }
};

string hashPassword(const string& password) {
    // Create a buffer to hold the hash
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    // Create a 'message digest context' to hold the operation's state
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        cerr << "Failed to create EVP_MD_CTX" << endl;
        return "";
    }

    // Initialize the digest operation, select the SHA256 algorithm
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        cerr << "Failed to initialize digest operation" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Provide the message to be digested
    if (EVP_DigestUpdate(mdctx, password.c_str(), password.size()) != 1) {
        cerr << "Failed to provide data to digest operation" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Retrieve the digest
    if (EVP_DigestFinal_ex(mdctx, hash, &lengthOfHash) != 1) {
        cerr << "Failed to finalize digest operation" << endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);

    // Convert the hash to a hex string
    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}



void newUser(User& user) {
    create_directories(filesystem::path(userDataFolder)); // Ensure the folder exists

    cout << "Enter your name: ";
    getline(cin, user.name);
    cout << "Enter your email: ";
    getline(cin, user.email);
    cout << "Set your password: ";
    getline(cin, user.passwordHash); 


    string hashedPassword = hashPassword(user.passwordHash); // Hash the user's password

    // Open the file for this user in the folder
    ofstream file(filesystem::path(userDataFolder) / (user.email + ".txt"));
    if (!file.is_open()) {
        cerr << "Error creating file for user.\n";
        return;
    }

    // Write the email, hashed password, and name
    file << user.email << "\n" << hashedPassword << endl;
    cout << "Thank you for signing up with us, " << user.name << "!\n";
}


bool verifyUser(const string& email, const string& inputPassword, User& user) {
    filesystem::path filePath = filesystem::path(userDataFolder) / (email + ".txt");

    ifstream file(filePath);
    if (!file) {
        cout << "User not found.\n";
        return false;
    }

    // Directly read the email and hashed password
    string storedEmail, storedHashedPassword, name;
    getline(file, storedEmail); // Read stored email (first line)
    getline(file, storedHashedPassword); // Read stored hashed password (second line)

    // Compare hashed values
    if (hashPassword(inputPassword) == storedHashedPassword) {
        // Assuming User has a constructor or method to initialize it properly
        user.email = email;
        user.passwordHash = storedHashedPassword; // To add to user file incase of password deletion
        user.name = name; // Assign the read name to the user object

        cout << "Login successful. Welcome back, " << name << "!\n";
        // Proceed with showing the user menu or further actions
        return true;
    }
    else {
        cout << "Invalid password.\n";
        return false;
    }
}



string generateRandomPassword() {
    string chars =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "!@#$%^&*()";
    string password;
    srand(static_cast<unsigned>(time(nullptr)));
    int length = rand() % 5 + 8; // Length between 8 and 12
    for (int i = 0; i < length; ++i) {
        password += chars[rand() % chars.length()];
    }
    return password;
}

void addUserPassword(User& user) {
    string label, passwordChoice, password;
    cout << "Please enter a label for your new password: ";
    getline(cin, label);
    cout << "Would you like to generate a new password? (yes/no): ";
    getline(cin, passwordChoice);
    if (passwordChoice == "yes" || passwordChoice == "Yes") {
        password = generateRandomPassword();
        cout << "Generated Password: " << password << endl;
    }
    else {
        cout << "Enter your password: ";
        getline(cin, password);
    }

    //Use Hexadecimal values to avoid usage of null terminator
    unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                         0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                         0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31 };
    unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

    unsigned char plaintext[1024]; // Make sure this buffer is large enough
    strncpy_s((char*)plaintext, sizeof(plaintext), password.c_str(), _TRUNCATE);
    // Ensure null termination
    int plaintext_len = strlen((char*)plaintext);

    unsigned char ciphertext[1024]; // Adjust size as needed
    int ciphertext_len;

    // Encrypt the password
    if (encrypt(plaintext, plaintext_len, key, iv, ciphertext, ciphertext_len)) {
        // Convert binary ciphertext to hex string for storage
        string encryptedPasswordHex = bin2hex(ciphertext, ciphertext_len);

       
        user.passwords.put(label, encryptedPasswordHex); //Adding password to the hashtable


        //Adding password to user data file
        ofstream file(filesystem::path(userDataFolder) / (user.email + ".txt"), ios::app); 
        if (!file) {
            cout << "Error updating file for user.\n";
            return;
        }
        file << label << " " << encryptedPasswordHex << endl;
        cout << "Password added to your keychain.\n";
    }
    else {
        cerr << "Encryption failed.\n";
    }
}

// Method to start the application engine
void showMenu(User& user) {
    int choice;
    do {
        cout << "------------------------------------------------\n";
        cout << "What would you like to do?\n";
        cout << "1. Display a specific password by choosing a label\n";
        cout << "2. Display all passwords\n";
        cout << "3. Add a new password\n";
        cout << "4. Delete a password\n";
        cout << "5. Log Out and Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        cout << "------------------------------------------------\n";

        switch (choice) {
        case 1: {
            cout << "Available labels:\n";
            user.passwords.forEachEntry([](const string& key, const string& value) {
                cout << "- " << key << endl;  // Display key; ignore value
                });

            cout << "Enter the label of the password you want to display: ";
            string chosenLabel;
            getline(cin, chosenLabel);

            string encryptedPasswordHex = user.passwords.get(chosenLabel);
            if (!encryptedPasswordHex.empty()) {
                vector<unsigned char> encryptedPasswordBin;
                if (hex2bin(encryptedPasswordHex, encryptedPasswordBin)) {
                    unsigned char decryptedPassword[1024]; // Ensure this buffer is large enough
                    int decryptedPasswordLen = 0;

                    //Use Hexadecimal values to avoid usage of null terminator
                    unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                         0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                         0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                         0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31 };
                    unsigned char iv[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

                    // Decrypt the password
                    if (decrypt(encryptedPasswordBin.data(), encryptedPasswordBin.size(), key, iv, decryptedPassword, decryptedPasswordLen)) {
                        decryptedPassword[decryptedPasswordLen] = '\0'; // Null-terminate the decrypted password
                        cout << "Password for " << chosenLabel << " is: " << decryptedPassword << endl;
                    }
                    else {
                        cout << "Failed to decrypt password for " << chosenLabel << endl;
                    }
                }
                else {
                    cout << "Failed to convert encrypted password to binary for " << chosenLabel << endl;
                }
            }
            else {
                cout << "No password found for label: " << chosenLabel << endl;
            }
            break;
        }

        case 2:
            cout << "Stored passwords:\n";
            user.displayAll();
            break;
        case 3:
            addUserPassword(user);
            break;
        case 4: {
            cout << "Available labels:\n";
            user.passwords.forEachEntry([](const string& key, const string& value) {
                cout << "- " << key << endl;  // Display key; ignore value
                });
            cout << "Enter the label of the password you want to delete: ";
            string label;
            getline(cin, label);

            if (user.passwords.remove(label)) {
                cout << "Password deleted successfully.\n";
                user.savePasswords(); // Save the updated list of passwords to the file
            }
            else {
                cout << "No password found for label: " << label << ".\n";
            }
            break;
        }

        case 5:
            cout << "Logging out...\n";
            break;

        default:
            cout << "Invalid option. Please try again.\n";
        }
        cout << "------------------------------------------------\n";
    } while (choice != 5);
}


int main() {
    int option;
    User user; 
    bool isLoggedIn = false;

    cout << "Please choose an option: \n1. Sign Up\n2. Login\n";
    cout << "Enter your choice: ";
    cin >> option;
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Clear the input buffer

    if (option == 1) {
        User new_User;
        newUser(new_User); 
        user = new_User; 
        if (user.loadPasswords()) {
            isLoggedIn = true;
            cout << "Welcome, " << user.name << "! You are now logged in.\n";
        }
    }
    else if (option == 2) {
        string email, password;
        // Prompt for user login
        cout << "Enter your email: ";
        getline(cin, email);
        cout << "Enter your password: ";
        getline(cin, password);

        if (verifyUser(email, password, user)) {
            isLoggedIn = true;
            user.loadPasswords();
            cout << "Welcome back, " << user.name << "!\n";
        }
        else {
            cout << "Invalid login. Please check your email and password.\n";
        }
    }
    else {
        cout << "Invalid option selected.\n";
    }

    if (isLoggedIn) {
        showMenu(user); // Show the menu for the logged-in user.
    }

    return 0;
}