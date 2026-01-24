package grpc

import (
	"context"

	"usermc/cmd/app/usecase"
	"usermc/proto/userpb"
)

type GRPCServer struct {
	userpb.UnimplementedUserServiceServer
	UserUsecase usecase.UserUsecase
}

func (s *GRPCServer) GetUserInfoByUserID(
	ctx context.Context,
	req *userpb.GetUserInfoRequest,
) (*userpb.GetUserInfoResult, error) {

	userInfo, err := s.UserUsecase.GetUserById(ctx, req.UserId)
	if err != nil {
		return nil, err
	}

	return &userpb.GetUserInfoResult{
		Id:        userInfo.ID,
		Name:      userInfo.Name,
		Email:     userInfo.Email,
		Phone:     derefString(userInfo.Phone),
		AvatarUrl: derefString(userInfo.AvatarURL),
		Role:      userInfo.Role,
	}, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
