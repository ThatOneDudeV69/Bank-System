#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <sqlite3.h>
#include <openssl/sha.h>

using namespace std;

sqlite3* db;  // Database connection

// Hash function (SHA-256)
string sha256(const string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];

    return ss.str();
}

// Database setup
void setupDatabase() {
    sqlite3_open("bank.db", &db);
    string usersTable = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, balance REAL DEFAULT 0, loan REAL DEFAULT 0, loan_due INTEGER DEFAULT 0);";
    sqlite3_exec(db, usersTable.c_str(), nullptr, nullptr, nullptr);

    // Check if admin exists, if not, add it
    string adminCheck = "SELECT COUNT(*) FROM users WHERE username='admin';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, adminCheck.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    int adminExists = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (adminExists == 0) {
        string hashedPassword = sha256("PasswordNotSecure123");
        string insertAdmin = "INSERT INTO users (username, password, balance) VALUES ('admin', '" + hashedPassword + "', 1000000);";
        sqlite3_exec(db, insertAdmin.c_str(), nullptr, nullptr, nullptr);
    }
}

// User authentication
bool login(string username, string password) {
    string hashedPassword = sha256(password);
    string query = "SELECT COUNT(*) FROM users WHERE username='" + username + "' AND password='" + hashedPassword + "';";
    
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    bool authenticated = (sqlite3_column_int(stmt, 0) > 0);
    sqlite3_finalize(stmt);

    return authenticated;
}

// Get user balance
double getBalance(string username) {
    string query = "SELECT balance FROM users WHERE username='" + username + "';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    double balance = sqlite3_column_double(stmt, 0);
    sqlite3_finalize(stmt);
    return balance;
}

// Deposit money
void deposit(string username, double amount) {
    if (amount <= 0) {
        cout << "Invalid deposit amount.\n";
        return;
    }
    string updateQuery = "UPDATE users SET balance = balance + " + to_string(amount) + " WHERE username='" + username + "';";
    sqlite3_exec(db, updateQuery.c_str(), nullptr, nullptr, nullptr);
    cout << "Deposited $" << amount << ". New Balance: $" << getBalance(username) << endl;
}

// Withdraw money
void withdraw(string username, double amount) {
    double balance = getBalance(username);
    if (amount > balance || amount <= 0) {
        cout << "Invalid withdrawal amount.\n";
        return;
    }
    string updateQuery = "UPDATE users SET balance = balance - " + to_string(amount) + " WHERE username='" + username + "';";
    sqlite3_exec(db, updateQuery.c_str(), nullptr, nullptr, nullptr);
    cout << "Withdrawn $" << amount << ". New Balance: $" << getBalance(username) << endl;
}

// Request loan
void requestLoan(string username, double amount) {
    if (amount <= 0) {
        cout << "Invalid loan amount.\n";
        return;
    }

    string query = "SELECT loan FROM users WHERE username='" + username + "';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    double existingLoan = sqlite3_column_double(stmt, 0);
    sqlite3_finalize(stmt);

    if (existingLoan > 0) {
        cout << "You already have an active loan.\n";
        return;
    }

    cout << "Loan request sent to admin for approval.\n";
}

// Approve Loan (Admin Only)
void approveLoan(string username, double amount) {
    double totalRepayment = amount * 1.05;  // 5% interest
    time_t now = time(nullptr);
    int dueDate = now + (7 * 86400);  // 7 days from now

    string query = "UPDATE users SET loan=" + to_string(totalRepayment) + ", loan_due=" + to_string(dueDate) + " WHERE username='" + username + "';";
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    cout << "Loan of $" << totalRepayment << " approved for " << username << ".\n";
}

// Repay Loan
void repayLoan(string username) {
    string query = "SELECT loan, loan_due FROM users WHERE username='" + username + "';";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    double loanAmount = sqlite3_column_double(stmt, 0);
    time_t dueDate = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (loanAmount == 0) {
        cout << "No active loan.\n";
        return;
    }

    time_t now = time(nullptr);
    if (now > dueDate) {
        int daysLate = (now - dueDate) / 86400;
        loanAmount *= (1 + (0.005 * daysLate));
    }

    if (getBalance(username) < loanAmount) {
        cout << "Not enough funds to repay loan.\n";
        return;
    }

    string updateQuery = "UPDATE users SET balance = balance - " + to_string(loanAmount) + ", loan = 0, loan_due = 0 WHERE username='" + username + "';";
    sqlite3_exec(db, updateQuery.c_str(), nullptr, nullptr, nullptr);
    cout << "Loan repaid. Remaining Balance: $" << getBalance(username) << endl;
}

// Main function
int main() {
    setupDatabase();
    string username, password;
    
    cout << "Username: ";
    cin >> username;
    cout << "Password: ";
    cin >> password;

    if (!login(username, password)) {
        cout << "Invalid credentials.\n";
        return 0;
    }

    cout << "Welcome, " << username << "!\n";
    deposit(username, 500);
    requestLoan(username, 1000);
    approveLoan(username, 1000);
    repayLoan(username);

    sqlite3_close(db);
    return 0;
}
