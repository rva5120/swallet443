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
	"time"
	"strings"
	"math/rand"
	"github.com/pborman/getopt"
	"encoding/base64"
	"crypto/sha1"
	"crypto/hmac"
	"strconv"
	"encoding/hex"
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
	password_1 := "test"
	password_2 := "test"

	// 2. Compare the passwords and store it if they are the same
	if password_1 == password_2 {
		// Store the password
		copy(wal443.masterPassword[:], password_1)
	} else {
		// Passwords don't match, so throw an error
		fmt.Printf("ERROR passwords did not match\n")
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
	file_contents := systemTime.String() + pipe_symbols + generation_number_str + pipe_symbols
	file_contents_arr := []byte(file_contents)
	_, err2 := file.WriteString(file_contents)
	if err2 != nil {
		panic(err)
	}
	file.WriteString("\n")

	// 7. Convert masterPassword to 128-bit AES: w_k = truncate(16, sha1(masterPassword))
	masterPassword_sha1 := sha1.Sum(wal443.masterPassword)
	w_k := masterPassword_sha1[:16]

	// 8. Perform HMAC(key = w_k, message = lines in the file)
	HMAC_calc := hmac.New(sha1.New, w_k)
	HMAC_calc.Write(file_contents_arr)
	file_hmac := HMAC_calc.Sum(nil)

	// 9. Perform base64 encoding of hmac
	file_hmac_base64 := base64.StdEncoding.EncodeToString(file_hmac)

	// 10. Add HMAC to the file
	file_hmac_base64_str := string(file_hmac_base64[:])
	_, err3 := file.WriteString(file_hmac_base64_str)
	if err3 != nil {
		panic(err3)
	}
	file.WriteString("\n")

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
	// DO THE LOADING HERE

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

	// Process the command 
	switch command {
	case "add":
		// DO SOMETHING HERE, e.g., wal443.addPassword(...)

	case "del":
		// DO SOMETHING HERE
		
	case "show":
		// DO SOMETHING HERE
		
	case "chpw":
		// DO SOMETHING HERE
		
	case "reset":
		// DO SOMETHING HERE
		
	case "list":
		// DO SOMETHING HERE
		
	default:
		// Handle error, return failure
		fmt.Fprintf(os.Stderr, "Bad/unknown command for wallet [%s], aborting.\n", command)
		return false
	}

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
