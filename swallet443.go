////////////////////////////////////////////////////////////////////////////////
//
//  File           : swallet443.go
//  Description    : This is the implementaiton file for the swallet password
//                   wallet program program.  See assignment details.
//
//  Collaborators  : Raquel Alvarez
//  Last Modified  : 12/7/2017
//

// Package statement
package main

// Imports
import (
	"fmt"
	"os"
	"bufio"
	"time"
	"strings"
	"math/rand"
	"github.com/pborman/getopt"
	"github.com/howeyc/gopass"
	"encoding/base64"
	"crypto/sha1"
	"crypto/hmac"
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"encoding/hex"
	"regexp"
	// There will likely be several mode APIs you need
)

// Type definition  ** YOU WILL NEED TO ADD TO THESE **

// A single password
type walletEntry struct {
	password []byte    // Should be exactly 32 bytes with zero right padding
	salt []byte        // Should be exactly 16 bytes 
	comment []byte     // Should be exactly 128 bytes with zero right padding
}

// The wallet as a whole
type wallet struct {
	filename string
	masterPassword []byte   // Should be exactly 32 bytes with zero right padding
	passwords []walletEntry
}


// Global data
var usageText string = `USAGE: swallet443 [-h] [-v] <wallet-file> [create|add|del|show|chpw|reset|list]

where:
    -h - help mode (display this message)
    -v - enable verbose output

    <wallet-file> - wallet file to manage
    [create|add|del|show|chpw] - is a command to execute, where

     create - create a new wallet file
     add - adds a password to the wallet
     del - deletes a password from the wallet
     show - show a password in the wallet
     chpw - changes the password for an entry in the wallet
     reset - changes the password for the wallet
     list - list the entries in the wallet (without passwords)`

var verbose bool = true

var file_contents string = ""
var file_hmac_base64 string = ""
var generation_number int = 0
var w_k []byte
// You may want to create more global variables

//
// Functions

// Up to you to decide which functions you want to add

////////////////////////////////////////////////////////////////////////////////
//
// Function     : walletUsage
// Description  : This function prints out the wallet help
//
// Inputs       : none
// Outputs      : none

func walletUsage() {
	fmt.Fprintf(os.Stderr, "%s\n\n", usageText)
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : createWallet
// Description  : This function creates a wallet if it does not exist
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func createWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet
	wal443.filename = filename
	wal443.masterPassword = make([]byte, 32, 32) // You need to take it from here

	// Open/Create Wallet file
	file, err := os.Create(wal443.filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// WALLET [Password, Salt, Comment]
	// 1. Prompt the user for a master password twice (do not echo when entering)
	// UI NEEDED
	fmt.Printf("\x1b[34;1mPlease enter your password: ")
	pass_1, _ := gopass.GetPasswd()
	fmt.Printf("P\x1b[34;1mPlease re-enter your password: ")
	pass_2, _ := gopass.GetPasswd()
	password_1 := string(pass_1)
	password_2 := string(pass_2)
	//password_1 := "test2"
	//password_2 := "test2"

	// 2. Compare the passwords and store it if they are the same
	if password_1 == password_2 {
		// Store the password
		copy(wal443.masterPassword, password_1)
	} else {
		// Passwords don't match, so throw an error
		fmt.Printf("\x1b[31;1mERROR passwords did not match\n")
		os.Exit(-1)
	}

	// 3. Set System Time of Last Modification (time.Now())
	systemTime := time.Now()

	// 4. Set Generation Number (num of times the file has been modified)
	generation_number := 1
	generation_number_str := strconv.Itoa(generation_number)

	// 5. Setup || to write to file
	const pipe_symbols_hex = "7c7c"
	pipe_symbols_dec, _ := hex.DecodeString(pipe_symbols_hex)
	pipe_symbols := string(pipe_symbols_dec)

	// 6. Write contents to the file and setup data for the hmac
	file_contents = systemTime.String() + pipe_symbols + generation_number_str + pipe_symbols
	file_contents_arr := []byte(file_contents)

	// 7. Convert masterPassword to 128-bit AES: w_k = truncate(16, sha1(masterPassword))
	masterPassword_sha1 := sha1.Sum(wal443.masterPassword)
	w_k = masterPassword_sha1[:16]

	// 8. Perform HMAC(key = w_k, message = lines in the file)
	HMAC_calc := hmac.New(sha1.New, w_k)
	HMAC_calc.Write(file_contents_arr)
	file_hmac := HMAC_calc.Sum(nil)

	// 9. Perform base64 encoding of hmac
	file_hmac_base64 = base64.StdEncoding.EncodeToString(file_hmac)

	file_contents = file_contents + "\n"

	// Return the wall
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : loadWallet
// Description  : This function loads an existing wallet
//
// Inputs       : filename - the name of the wallet file
// Outputs      : the wallet if created, nil otherwise

func loadWallet(filename string) *wallet {

	// Setup the wallet
	var wal443 wallet
	wal443.masterPassword = make([]byte, 32, 32) // You need to take it from here
	wal443.passwords = make([]walletEntry, 0)
	// DO THE LOADING HERE

	// Set wallet filename
	wal443.filename = filename

	// Prompt user for master password
	// UI NEEDED
	//password := "test2"
	fmt.Printf("\x1b[92;1mPlease enter your password: \x1b[0m")
	pass, _ := gopass.GetPasswd()
	password := string(pass)
	copy(wal443.masterPassword, password)

	// Load Entries, if any
	// Open the file
	file, err := os.Open(wal443.filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Start Reading the file...
	scanner := bufio.NewScanner(file)

	// Line counter
	first_line_counter := 0

	// Process file
	for scanner.Scan() {

		line := scanner.Text()

		if first_line_counter == 0 {
			// Get generation number
			line_slice := strings.Split(line, "||")
			generation_number_str := line_slice[1]
			generation_number, _ = strconv.Atoi(generation_number_str)
			first_line_counter++
			file_contents = file_contents + line	// to compute hmac later
		} else {
			// Using regex, check if last line
			pipe_regex := regexp.MustCompile(`\x7c\x7c`)
			if pipe_regex.MatchString(line) {
				// Get entry number, salt, password, and comment
				line_slice := strings.Split(line, "||")
				//entry, _ := strconv.Atoi(line_slice[0])
				salt := []byte(line_slice[1])
				password := []byte(line_slice[2])
				comment := []byte(line_slice[3])
				// Decode from base64
				salt,_ = base64.StdEncoding.DecodeString(string(salt))
				password,_ = base64.StdEncoding.DecodeString(string(password))
				// Set entry values
				var new_entry walletEntry
				new_entry.salt = salt
				new_entry.password = password
				new_entry.comment = comment
				wal443.passwords = append(wal443.passwords, new_entry)
				file_contents = file_contents + line	// to compute hmac later
			} else {
				// Load last line into the file_hmac_base64 variable
				file_hmac_base64 = line
			}
		}
	}

	// Check validity of password
	// Convert masterPassword to 128-bit AES: w_k = truncate(16, sha1(masterPassword))
	masterPassword_sha1 := sha1.Sum(wal443.masterPassword)
	w_k = masterPassword_sha1[:16]

	// Perform HMAC(key = w_k, message = lines in the file)
	HMAC_calc := hmac.New(sha1.New, w_k)
	file_contents_arr := []byte(file_contents)
	HMAC_calc.Write(file_contents_arr)
	new_hmac := HMAC_calc.Sum(nil)

	// Revert base64 encoding of file hmac
	file_hmac, _ := base64.StdEncoding.DecodeString(file_hmac_base64)

	// Check if the two hashes are equal
	if !(hmac.Equal(file_hmac, new_hmac)) {
		// Wrong password entered
		fmt.Printf("\x1b[31;3mAborting, wrong password entered!!\n")
		os.Exit(-1)
	}

	file_contents = file_contents + "\n"

	// Return the wall
	return &wal443
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : saveWallet
// Description  : This function save a wallet to the file specified
//
// Inputs       : walletFile - the name of the wallet file
// Outputs      : true if successful test, false if failure

func (wal443 wallet) saveWallet() bool {

	// Setup the wallet
	f, _ := os.Create(wal443.filename)
	defer f.Close()

	wallet_file_content := file_contents + file_hmac_base64 + "\n"
	w := bufio.NewWriter(f)
	defer w.Flush()

	w.WriteString(wallet_file_content)

	// Return successfully
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : processWalletCommand
// Description  : This is the main processing function for the wallet
//
// Inputs       : walletFile - the name of the wallet file
//                command - the command to execute
// Outputs      : true if successful test, false if failure

func (wal443 wallet) processWalletCommand(command string) bool {

	// Update Last modified time and generation number
	const pipe_symbols_hex = "7c7c"
	pipe_symbols_dec, _ := hex.DecodeString(pipe_symbols_hex)
	pipe_symbols := string(pipe_symbols_dec)
	generation_number_str := strconv.Itoa(generation_number + 1)
	systemTime := time.Now()
	file_contents_for_hmac := systemTime.String() + pipe_symbols + generation_number_str + pipe_symbols
	file_contents = file_contents_for_hmac + "\n"

	// Process the command 
	switch command {
	case "add":
		// Prompt the user for a password
		// UI NEEDED
		//password := "testing"
		fmt.Printf("\x1b[92mPlease enter the new password you would like to store: ")
		pass,_ := gopass.GetPasswd()
		password := string(pass)
		pwd := make([]byte, 16, 16)
		copy(pwd, password)
		// Make new entry for passwords[]
		var new_entry walletEntry
		// Generate salt
		rand.Seed(time.Now().UnixNano())
		salt := make([]byte, 16)
		rand.Read(salt)
		// Encrypt password
		block,_ := aes.NewCipher(w_k)
		aesgcm,_ := cipher.NewGCMWithNonceSize(block,16)	// must specify nonce size or it doesn't take our salt
		encrypted_password := aesgcm.Seal(nil, salt, pwd, nil)
		// Prompt the user for a comment
		// UI NEEDED
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\x1b[92mPlease enter a description/comment about this password (press Enter when finished): ")
		comment, _ := reader.ReadString('\n')
		comment = strings.TrimSuffix(comment, "\n")
		//comment := "comment"
		comment_padded := make([]byte, 128, 128)
		copy(comment_padded, comment)
		// Zero right pad password
		//pwd = make([]byte, 32, 32)
		//copy(pwd, encrypted_password)
		pwd = encrypted_password
		// Save salt, password and comment to passwords[]
		new_entry.salt = salt
		new_entry.password = pwd
		new_entry.comment = comment_padded
		wal443.passwords = append(wal443.passwords, new_entry)

	case "del":
		// Prompt the user for a password
		// UI NEEDED
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\x1b[91mWhich entry would you like to delete (use list/show to see more): ")
		entry,_ := reader.ReadString('\n')
		entry = strings.TrimSuffix(entry, "\n")
		//entry := "1"
		entry_int, _ := strconv.Atoi(entry)
		pos := entry_int - 1
		// Remove entry
		wal443.passwords = append(wal443.passwords[:pos], wal443.passwords[pos+1:]...)

	case "show":
		// Prompt the user for keyword in comment
		// UI NEEDED
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\x1b[93mEnter a keyword present on the comment of the entries you would like to see displayed: ")
		keyword,_ := reader.ReadString('\n')
		keyword = strings.TrimSuffix(keyword, "\n")
		//keyword := "comment"
		// Look for keyword in comments of each entry in passwords[]
		for index, entry := range wal443.passwords {
			// when found, decrypt password and show entry, password and comment
			// regex
			found, _ := regexp.MatchString(keyword+".*", string(entry.comment))
			if found {
				// Decrypt password
				block, _ := aes.NewCipher(w_k)
				aesgcm, _ := cipher.NewGCMWithNonceSize(block,16)
				password,_ := aesgcm.Open(nil, entry.salt, entry.password, nil)
				pwd := string(password)
				// Show entry, password and comment
				fmt.Printf("\x1b[97mEntry %d \t Password: %s \t Comments: %s\n",index+1, pwd, string(entry.comment))
			}
		}

	case "chpw":
		// Prompt the user for entry number to change password
		// UI NEEDED
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\x1b[94mProvide the entry number of teh password you would like to change: ")
		entry,_ := reader.ReadString('\n')
		entry = strings.TrimSuffix(entry, "\n")
		//entry := "1"
		pos, _ := strconv.Atoi(entry)
		pos = pos - 1
		// Prompt the user for new password
		// UI NEEDED
		fmt.Printf("\x1b[94mEnter the new password for this entry: ")
		pass,_ := gopass.GetPasswd()
		password := string(pass)
		//password := "testing2"
		pwd := make([]byte, 16, 16)
		copy(pwd, password)
		// 128-bit AES encrypt the password: AES(w_k, salt|pwd)
		salt := wal443.passwords[pos].salt
		block,_ := aes.NewCipher(w_k)
		aesgcm,_ := cipher.NewGCMWithNonceSize(block,16)
		encrypted_password := aesgcm.Seal(nil, salt, pwd, nil)
		// Save password to entry in passwords[]
		wal443.passwords[pos].password = encrypted_password

	case "reset":
		// Prompt the user for a new password
		// UI NEEDED
		fmt.Printf("\x1b[95mPlease enter the new file password: ")
		pass,_ := gopass.GetPasswd()
		password := string(pass)
		//password := "test2"
		new_masterPassword := make([]byte, 32, 32)
		copy(new_masterPassword, password)
		// Generate new master key
		masterPassword_sha1 := sha1.Sum(new_masterPassword)
		new_w_k := masterPassword_sha1[:16]
		// For every password, decrypt it, and encrypt it again with new password
		for index, entry := range wal443.passwords {
			// Decrypt with old key
			block, _ := aes.NewCipher(w_k)
			aesgcm, _ := cipher.NewGCMWithNonceSize(block,16)
			decrypted_password,_ := aesgcm.Open(nil, entry.salt, entry.password, nil)
			// Encrypt with new key
			block,_ = aes.NewCipher(new_w_k)
			aesgcm,_ =cipher.NewGCMWithNonceSize(block,16)
			encrypted_password := aesgcm.Seal(nil, entry.salt, decrypted_password, nil)
			wal443.passwords[index].password = encrypted_password
			//fmt.Printf("New Password encrypted %s\n", encrypted_password)
			//fmt.Printf("Password decrypted %s\n", decrypted_password)
		}
		// Update master key and password
		w_k = new_w_k
		copy(wal443.masterPassword, password)

	case "list":
		// Iterate through the wallet entries, and print entry num, and comments
		for index,entry := range wal443.passwords {
			comments := string(entry.comment)
			fmt.Printf("\x1b[96mEntry %d \t Comments: %s\n", index+1, comments)
		}

	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "\x1b[31;3mBad/unknown command for wallet [%s], aborting.\n", command)
		return false
	}

	// Update file_contents for saving...
	// Add entry number || salt || password || comment \n to file_contents for every entry
	// Simultaneously, add the same infor without \n to file_contents_for_hmac
	for index, entry := range wal443.passwords {
		// file_contents
		// base64 encode salt and password
		salt_base64 := base64.StdEncoding.EncodeToString(entry.salt)
		pass_base64 := base64.StdEncoding.EncodeToString(entry.password)
		index++
		file_contents_for_hmac = file_contents_for_hmac + strconv.Itoa(index) + "||" + salt_base64 + "||" + pass_base64 + "||" + string(entry.comment)
		file_contents = file_contents + strconv.Itoa(index) + "||" + salt_base64 + "||" + pass_base64 + "||" + string(entry.comment) + "\n"
	}
	file_contents_for_hmac_arr := []byte(file_contents_for_hmac)

	// Update HMAC after changes for saving...
	HMAC_calc := hmac.New(sha1.New, w_k)
	HMAC_calc.Write(file_contents_for_hmac_arr)
	file_hmac := HMAC_calc.Sum(nil)

	// 9. Perform base64 encoding of hmac
	file_hmac_base64 = base64.StdEncoding.EncodeToString(file_hmac)

	// Return sucessfull
	return true
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the password generator program
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

func main() {

	// Setup options for the program content
	getopt.SetUsage(walletUsage)
	rand.Seed(time.Now().UTC().UnixNano())
	helpflag := getopt.Bool('h', "", "help (this menu)")
	verboseflag := getopt.Bool('v', "", "enable verbose output")

	// Now parse the command line arguments
	err := getopt.Getopt(nil)
	if err != nil {
		// Handle error
		fmt.Fprintln(os.Stderr, err)
		getopt.Usage()
		os.Exit(-1)
	}

	// Process the flags
	fmt.Printf("help flag [%t]\n", *helpflag)
	fmt.Printf("verbose flag [%t]\n", *verboseflag)
	verbose = *verboseflag
	if *helpflag == true {
		getopt.Usage()
		os.Exit(-1)
	}

	// Check the arguments to make sure we have enough, process if OK
	if getopt.NArgs() < 2 {
		fmt.Printf("Not enough arguments for wallet operation.\n")
		getopt.Usage()
		os.Exit(-1)
	}
	fmt.Printf("wallet file [%t]\n", getopt.Arg(0))
	filename := getopt.Arg(0)
	fmt.Printf("command [%t]\n", getopt.Arg(1))
	command := strings.ToLower(getopt.Arg(1))

	// Now check if we are creating a wallet
	if command == "create" {

		// Create and save the wallet as needed
		wal443 := createWallet(filename)
		if wal443 != nil {
			wal443.saveWallet()
		}

	} else {

		// Load the wallet, then process the command
		wal443 := loadWallet(filename)
		if wal443 != nil && wal443.processWalletCommand(command) {
			wal443.saveWallet()
		}

	}

	// Return (no return code)
	return
}
