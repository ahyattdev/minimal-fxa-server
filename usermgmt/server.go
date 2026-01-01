package usermgmt

import (
	"context"
	"log/slog"
	"net"
	"os"

	"github.com/ahyattdev/minimal-fxa-server/auth/local"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the UserManagement gRPC service
type Server struct {
	UnimplementedUserManagementServer
	provider *local.Provider
}

// NewServer creates a new user management gRPC server
func NewServer(provider *local.Provider) *Server {
	return &Server{
		provider: provider,
	}
}

// CreateUser creates a new local user
func (s *Server) CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	user, err := s.provider.CreateUser(ctx, req.Email, req.Password)
	if err != nil {
		slog.Error("Failed to create user", "email", req.Email, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &CreateUserResponse{
		UserId: user.ID,
		Email:  user.Email,
	}, nil
}

// DeleteUser deletes a local user
func (s *Server) DeleteUser(ctx context.Context, req *DeleteUserRequest) (*DeleteUserResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	err := s.provider.DeleteUser(ctx, req.Email)
	if err != nil {
		slog.Error("Failed to delete user", "email", req.Email, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to delete user: %v", err)
	}

	return &DeleteUserResponse{
		Success: true,
	}, nil
}

// ChangePassword changes a user's password
func (s *Server) ChangePassword(ctx context.Context, req *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	err := s.provider.ChangePassword(ctx, req.Email, req.NewPassword)
	if err != nil {
		slog.Error("Failed to change password", "email", req.Email, "error", err)
		return nil, status.Errorf(codes.Internal, "failed to change password: %v", err)
	}

	return &ChangePasswordResponse{
		Success: true,
	}, nil
}

// ListUsers lists all local users
func (s *Server) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	users, err := s.provider.ListUsers(ctx)
	if err != nil {
		slog.Error("Failed to list users", "error", err)
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	response := &ListUsersResponse{
		Users: make([]*User, len(users)),
	}
	for i, user := range users {
		response.Users[i] = &User{
			Id:    user.ID,
			Email: user.Email,
		}
	}

	return response, nil
}

// DefaultSocketPath is the default Unix socket path for user management
const DefaultSocketPath = "/tmp/fxa-usermgmt.sock"

// StartServer starts the gRPC server on a Unix socket
func StartServer(provider *local.Provider, socketPath string) error {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	// Remove existing socket file if it exists
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}

	// Set socket permissions (restrict access)
	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		return err
	}

	grpcServer := grpc.NewServer()
	RegisterUserManagementServer(grpcServer, NewServer(provider))

	slog.Info("User management gRPC server starting", "socket", socketPath)
	return grpcServer.Serve(listener)
}
