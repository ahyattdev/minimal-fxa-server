package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/ahyattdev/minimal-fxa-server/usermgmt"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	socketPath := os.Getenv("FXA_SOCKET")
	if socketPath == "" {
		socketPath = usermgmt.DefaultSocketPath
	}

	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := usermgmt.NewUserManagementClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch os.Args[1] {
	case "create":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fxa-user create <email>\n")
			os.Exit(1)
		}
		createUser(ctx, client, os.Args[2])

	case "delete":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fxa-user delete <email>\n")
			os.Exit(1)
		}
		deleteUser(ctx, client, os.Args[2])

	case "passwd":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fxa-user passwd <email>\n")
			os.Exit(1)
		}
		changePassword(ctx, client, os.Args[2])

	case "list":
		listUsers(ctx, client)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`fxa-user - Firefox Account user management CLI

Usage:
  fxa-user <command> [arguments]

Commands:
  create <email>   Create a new user (will prompt for password)
  delete <email>   Delete a user
  passwd <email>   Change a user's password
  list             List all users

Environment:
  FXA_SOCKET       Path to the gRPC Unix socket (default: /var/run/fxa/usermgmt.sock)`)
}

func createUser(ctx context.Context, client usermgmt.UserManagementClient, email string) {
	password, err := promptPassword("Password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}

	confirmPassword, err := promptPassword("Confirm password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if password != confirmPassword {
		fmt.Fprintf(os.Stderr, "Passwords do not match\n")
		os.Exit(1)
	}

	if len(password) < 8 {
		fmt.Fprintf(os.Stderr, "Password must be at least 8 characters\n")
		os.Exit(1)
	}

	resp, err := client.CreateUser(ctx, &usermgmt.CreateUserRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User created: %s (ID: %s)\n", resp.Email, resp.UserId)
}

func deleteUser(ctx context.Context, client usermgmt.UserManagementClient, email string) {
	fmt.Printf("Are you sure you want to delete user %s? [y/N]: ", email)
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != "y" && confirm != "Y" {
		fmt.Println("Cancelled")
		return
	}

	_, err := client.DeleteUser(ctx, &usermgmt.DeleteUserRequest{
		Email: email,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete user: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("User deleted: %s\n", email)
}

func changePassword(ctx context.Context, client usermgmt.UserManagementClient, email string) {
	password, err := promptPassword("New password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}

	confirmPassword, err := promptPassword("Confirm password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}

	if password != confirmPassword {
		fmt.Fprintf(os.Stderr, "Passwords do not match\n")
		os.Exit(1)
	}

	if len(password) < 8 {
		fmt.Fprintf(os.Stderr, "Password must be at least 8 characters\n")
		os.Exit(1)
	}

	_, err = client.ChangePassword(ctx, &usermgmt.ChangePasswordRequest{
		Email:       email,
		NewPassword: password,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to change password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password changed for: %s\n", email)
}

func listUsers(ctx context.Context, client usermgmt.UserManagementClient) {
	resp, err := client.ListUsers(ctx, &usermgmt.ListUsersRequest{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list users: %v\n", err)
		os.Exit(1)
	}

	if len(resp.Users) == 0 {
		fmt.Println("No users found")
		return
	}

	fmt.Printf("%-36s  %s\n", "ID", "Email")
	fmt.Println("------------------------------------  " + "----------------------------------------")
	for _, user := range resp.Users {
		fmt.Printf("%-36s  %s\n", user.Id, user.Email)
	}
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}
