package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Thought struct {
	ID           primitive.ObjectID `bson:"_id"`
	Thought_id   string             `json:"thought_id"`
	Thought_idea *string            `json:"thought_idea" validate:"required,min=1,max=250"`
	Likes        []string           `json:"likes"`
	User_id      string             `json:"user_id"`
	Created_at   time.Time          `json:"created_at"`
}
