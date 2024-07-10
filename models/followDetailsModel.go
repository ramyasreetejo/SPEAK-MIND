package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type MiniUser struct {
	User_id   string  `json:"user_id"`
	User_name *string `json:"user_name"`
}

type FollowDetails struct {
	ID        primitive.ObjectID `bson:"_id"`
	User_id   string             `json:"user_id"`
	User_name *string            `json:"user_name"`
	Followers []MiniUser         `json:"followers"`
	Following []MiniUser         `json:"following"`
}
