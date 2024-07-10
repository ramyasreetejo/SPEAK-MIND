package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator"
	"github.com/ramyasreetejo/speak-mind/contextKeys"
	"github.com/ramyasreetejo/speak-mind/database"
	"github.com/ramyasreetejo/speak-mind/helpers"
	"github.com/ramyasreetejo/speak-mind/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var followCollection *mongo.Collection = database.OpenCollection(database.Client, "follow")
var thoughtCollection *mongo.Collection = database.OpenCollection(database.Client, "thought")

var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""
	if err != nil {
		msg = "password is incorrect for the given email"
		check = false
	}
	return check, msg
}

func Signup(w http.ResponseWriter, r *http.Request) {
	// w.Write([]byte(`"message": "hi, signedup"`))
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()

	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validationErr := validate.Struct(user)
	if validationErr != nil {
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	password := HashPassword(*user.Password)
	user.Password = &password

	count_email, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	if err != nil {
		log.Panic(err)
		http.Error(w, "error occurred while checking for the email", http.StatusInternalServerError)
		return
	}

	count_phno, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
	if err != nil {
		log.Panic(err)
		http.Error(w, "error occurred while checking for the phone number", http.StatusInternalServerError)
		return
	}

	count_username, err := userCollection.CountDocuments(ctx, bson.M{"user_name": user.User_name})
	if err != nil {
		log.Panic(err)
		http.Error(w, "error occurred while checking for user name", http.StatusInternalServerError)
		return
	}

	if (count_email > 0) || (count_phno > 0) || (count_username > 0) {
		http.Error(w, "this email or phone number or user name already exists", http.StatusInternalServerError)
		return
	}

	user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	user.ID = primitive.NewObjectID()
	user.User_id = user.ID.Hex()
	token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
	user.Token = &token
	user.Refresh_token = &refreshToken

	resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
	if insertErr != nil {
		msg := "User item was not created"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	followDetails := models.FollowDetails{
		ID:        primitive.NewObjectID(),
		User_id:   user.User_id,
		User_name: user.User_name,
		Followers: []models.MiniUser{},
		Following: []models.MiniUser{},
	}

	_, followinsertErr := followCollection.InsertOne(ctx, followDetails)
	if followinsertErr != nil {
		msg := "Follow Details item was not created"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	cookie := &http.Cookie{
		Name:  "token",
		Value: *user.Token,
	}
	// Set the cookie in the response
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resultInsertionNumber)
}

func Login(w http.ResponseWriter, r *http.Request) {
	// fmt.Fprintf(w, "hi, loggedin")
	var ctx, cancel = context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	var loginDetails models.LoginDetails
	var foundUser models.User

	err := json.NewDecoder(r.Body).Decode(&loginDetails)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validationErr := validate.Struct(loginDetails)
	if validationErr != nil {
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	err = userCollection.FindOne(ctx, bson.M{"email": loginDetails.Email}).Decode(&foundUser)
	if err != nil {
		http.Error(w, "error: email doesn't exist in db", http.StatusBadRequest)
		return
	}

	passwordIsValid, msg := VerifyPassword(*loginDetails.Password, *foundUser.Password)
	if !passwordIsValid {
		http.Error(w, "error: "+msg, http.StatusUnauthorized)
		return
	}

	token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
	helpers.UpdateAllTokensToDB(token, refreshToken, foundUser.User_id)
	err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)

	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response

	w.Header().Set("Content-Type", "application/json")
	cookie := &http.Cookie{
		Name:  "token",
		Value: *foundUser.Token,
	}
	// Set the cookie in the response
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	// Write a response to the client
	json.NewEncoder(w).Encode(foundUser)
}

func GetUsers(w http.ResponseWriter, r *http.Request) {
	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// If user type is not ADMIN, return an error
	if err := helpers.CheckUserType(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set up context and cancellation function
	var ctx_new, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
	if err != nil || recordPerPage < 1 {
		recordPerPage = 10
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	startIndex := (page - 1) * recordPerPage
	// Overwrite startIndex if provided as query parameter
	if queryStartIndex := r.URL.Query().Get("startIndex"); queryStartIndex != "" {
		startIndex, err = strconv.Atoi(queryStartIndex)
		if err != nil || startIndex < 0 {
			startIndex = 0
		}
	}

	matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}}}}}

	// Perform aggregation query
	result, err := userCollection.Aggregate(ctx_new, mongo.Pipeline{
		matchStage, groupStage, projectStage})
	if err != nil {
		http.Error(w, "error: error occured while listing user items", http.StatusInternalServerError)
		return
	}

	// Extract results
	var allusers []bson.M
	if err = result.All(ctx_new, &allusers); err != nil {
		log.Fatal(err)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allusers[0])
}

func GetUser(w http.ResponseWriter, r *http.Request) {

	var userIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/users/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		userIdFromURL = pathSegments[0]
		fmt.Printf("User ID from URL, whose details to be fetched: %s\n", userIdFromURL)
	} else {
		http.Error(w, "User ID, whose details to be fetched is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Check if user_type is "ADMIN", if its "USER", they cant access this route unless the user logged in trying to access his details itself!
	if err := helpers.CheckUserTypeAndMatchUserIdFromURLToToken(r, userIdFromURL); err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusBadRequest)
		return
	}

	var user models.User
	err := userCollection.FindOne(context.Background(), bson.M{"user_id": userIdFromURL}).Decode(&user)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func Follow(w http.ResponseWriter, r *http.Request) {

	var userIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/user/follow")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		userIdFromURL = pathSegments[0]
		fmt.Printf("User ID from URL, who is to be followed: %s\n", userIdFromURL)
	} else {
		http.Error(w, "User ID, who is to be followed is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Check if user is trying to follow oneself!
	if userId == userIdFromURL {
		http.Error(w, "error: User trying to follow oneself!", http.StatusBadRequest)
		return
	}

	// get loggedin and followed users
	var LoggedinUser models.User
	err := userCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&LoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var FollowedUser models.User
	err = userCollection.FindOne(context.Background(), bson.M{"user_id": userIdFromURL}).Decode(&FollowedUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update following of LoggedinUser
	var followDetailsLoggedinUser models.FollowDetails
	err = followCollection.FindOne(context.Background(), bson.M{"user_id": LoggedinUser.User_id}).Decode(&followDetailsLoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followinglist := followDetailsLoggedinUser.Following
	followinglist = append(followinglist, models.MiniUser{
		User_id:   FollowedUser.User_id,
		User_name: FollowedUser.User_name,
	})
	var updateObj1 primitive.D
	updateObj1 = append(updateObj1, bson.E{Key: "following", Value: followinglist})
	upsert := true
	filter := bson.M{"user_id": LoggedinUser.User_id}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = followCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj1},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update followers of FollowedUser
	var followDetailsFollowedUser models.FollowDetails
	err = followCollection.FindOne(context.Background(), bson.M{"user_id": FollowedUser.User_id}).Decode(&followDetailsFollowedUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followerslist := followDetailsFollowedUser.Followers
	followerslist = append(followerslist, models.MiniUser{
		User_id:   LoggedinUser.User_id,
		User_name: LoggedinUser.User_name,
	})
	var updateObj2 primitive.D
	updateObj2 = append(updateObj2, bson.E{Key: "followers", Value: followerslist})
	upsert = true
	filter = bson.M{"user_id": FollowedUser.User_id}
	opt = options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = followCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj2},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Updated!")
}

func UnFollow(w http.ResponseWriter, r *http.Request) {

	var userIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/user/unfollow")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		userIdFromURL = pathSegments[0]
		fmt.Printf("User ID from URL, who is to be unfollowed: %s\n", userIdFromURL)
	} else {
		http.Error(w, "User ID, who is to be unfollowed is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Check if user is trying to unfollow oneself!
	if userId == userIdFromURL {
		http.Error(w, "error: User trying to unfollow oneself!", http.StatusBadRequest)
		return
	}

	// get loggedin and unfollowed users
	var LoggedinUser models.User
	err := userCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&LoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var UnFollowedUser models.User
	err = userCollection.FindOne(context.Background(), bson.M{"user_id": userIdFromURL}).Decode(&UnFollowedUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update following of LoggedinUser
	var followDetailsLoggedinUser models.FollowDetails
	err = followCollection.FindOne(context.Background(), bson.M{"user_id": LoggedinUser.User_id}).Decode(&followDetailsLoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followinglist := followDetailsLoggedinUser.Following
	var newfollowinglist []models.MiniUser
	for _, miniuser := range followinglist {
		if miniuser.User_id != UnFollowedUser.User_id {
			newfollowinglist = append(newfollowinglist, miniuser)
		}
	}
	var updateObj1 primitive.D
	updateObj1 = append(updateObj1, bson.E{Key: "following", Value: newfollowinglist})
	upsert := true
	filter := bson.M{"user_id": LoggedinUser.User_id}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = followCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj1},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update followers of FollowedUser
	var followDetailsUnFollowedUser models.FollowDetails
	err = followCollection.FindOne(context.Background(), bson.M{"user_id": UnFollowedUser.User_id}).Decode(&followDetailsUnFollowedUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followerslist := followDetailsUnFollowedUser.Followers
	var newfollowerslist []models.MiniUser
	for _, miniuser := range followerslist {
		if miniuser.User_id != LoggedinUser.User_id {
			newfollowerslist = append(newfollowerslist, miniuser)
		}
	}
	var updateObj2 primitive.D
	updateObj2 = append(updateObj2, bson.E{Key: "followers", Value: newfollowerslist})
	upsert = true
	filter = bson.M{"user_id": UnFollowedUser.User_id}
	opt = options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = followCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj2},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Updated!")
}

func GetFollowers(w http.ResponseWriter, r *http.Request) {

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	var followDetailsLoggedinUser models.FollowDetails
	err := followCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&followDetailsLoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followerslist := followDetailsLoggedinUser.Followers

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(followerslist)
}

func GetFollowing(w http.ResponseWriter, r *http.Request) {

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	var followDetailsLoggedinUser models.FollowDetails
	err := followCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&followDetailsLoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followinglist := followDetailsLoggedinUser.Following

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(followinglist)
}

func NewThought(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	var thought models.Thought
	err := json.NewDecoder(r.Body).Decode(&thought)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validationErr := validate.Struct(thought)
	if validationErr != nil {
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	thought.ID = primitive.NewObjectID()
	thought.Thought_id = thought.ID.Hex()
	thought.User_id = userId
	thought.Likes = []string{}
	thought.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

	resultInsertionNumber, insertErr := thoughtCollection.InsertOne(ctx, thought)
	if insertErr != nil {
		msg := "Thought item was not created"
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resultInsertionNumber)
}

func DeleteThought(w http.ResponseWriter, r *http.Request) {
	var thoughtIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/user/deletethought/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		thoughtIdFromURL = pathSegments[0]
		fmt.Printf("Thought ID from URL, whose thought is to be deleted: %s\n", thoughtIdFromURL)
	} else {
		http.Error(w, "Thought ID, whose thought is to be deleted is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	var thoughtFromURL models.Thought
	err := thoughtCollection.FindOne(ctx, bson.M{"thought_id": thoughtIdFromURL}).Decode(&thoughtFromURL)
	if err != nil {
		http.Error(w, "error: Thought with Thought_id doesn't exist in db", http.StatusBadRequest)
		return
	}

	filter := bson.M{"thought_id": thoughtFromURL.Thought_id}
	del_result, err := followCollection.DeleteOne(
		ctx,
		filter,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(del_result)
}

func LikeThought(w http.ResponseWriter, r *http.Request) {
	var thoughtIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/user/thought/like/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		thoughtIdFromURL = pathSegments[0]
		fmt.Printf("Thouht ID from URL, that is to be liked: %s\n", thoughtIdFromURL)
	} else {
		http.Error(w, "Thought ID, that is to be liked is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// get LoggedinUser
	var LoggedinUser models.User
	err := userCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&LoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// get thought from thought id
	var LikedThought models.Thought
	err = thoughtCollection.FindOne(context.Background(), bson.M{"thought_id": thoughtIdFromURL}).Decode(&LikedThought)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update like of LoggedinUser
	likeslist := LikedThought.Likes
	if res := sort.SearchStrings(likeslist, *LoggedinUser.User_name); res == len(likeslist) {
		likeslist = append(likeslist, *LoggedinUser.User_name)
	} else {
		http.Error(w, "error: LoggedinUser has already liked this thought.", http.StatusBadRequest)
		return
	}

	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{Key: "likes", Value: likeslist})
	upsert := true
	filter := bson.M{"thought_id": LikedThought.Thought_id}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = thoughtCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Like Updated!")
}

func UnlikeThought(w http.ResponseWriter, r *http.Request) {
	var thoughtIdFromURL string

	path := strings.TrimPrefix(r.URL.Path, "/user/thought/unlike/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		thoughtIdFromURL = pathSegments[0]
		fmt.Printf("Thouht ID from URL, that is to be liked: %s\n", thoughtIdFromURL)
	} else {
		http.Error(w, "Thought ID, that is to be liked is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// get LoggedinUser
	var LoggedinUser models.User
	err := userCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&LoggedinUser)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// get thought from thought id
	var LikedThought models.Thought
	err = thoughtCollection.FindOne(context.Background(), bson.M{"thought_id": thoughtIdFromURL}).Decode(&LikedThought)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// update like of LoggedinUser
	likeslist := LikedThought.Likes
	var newlikeslist []string
	if res := sort.SearchStrings(likeslist, *LoggedinUser.User_name); res != len(likeslist) {
		for _, likeduser := range likeslist {
			if likeduser != *LoggedinUser.User_name {
				newlikeslist = append(newlikeslist, likeduser)
			}
		}
	} else {
		http.Error(w, "error: LoggedinUser did not like this thought in the first place.", http.StatusBadRequest)
		return
	}

	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{Key: "likes", Value: newlikeslist})
	upsert := true
	filter := bson.M{"thought_id": LikedThought.Thought_id}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}
	_, err = thoughtCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{Key: "$set", Value: updateObj},
		},
		&opt,
	)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("Unlike Updated!")
}

func GetMyThoughts(w http.ResponseWriter, r *http.Request) {
	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Set up context and cancellation function
	var ctx_new, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
	if err != nil || recordPerPage < 1 {
		recordPerPage = 10
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	startIndex := (page - 1) * recordPerPage
	// Overwrite startIndex if provided as query parameter
	if queryStartIndex := r.URL.Query().Get("startIndex"); queryStartIndex != "" {
		startIndex, err = strconv.Atoi(queryStartIndex)
		if err != nil || startIndex < 0 {
			startIndex = 0
		}
	}

	matchStage := bson.D{{Key: "$match", Value: bson.D{{Key: "user_id", Value: userId}}}}
	sortStage := bson.D{{Key: "$sort", Value: bson.D{{Key: "created_at", Value: -1}}}} // Sort by created_at descending
	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}}}}}

	// Perform aggregation query
	result, err := thoughtCollection.Aggregate(ctx_new, mongo.Pipeline{
		matchStage, sortStage, groupStage, projectStage})
	if err != nil {
		http.Error(w, "error: error occured while listing thought items", http.StatusInternalServerError)
		return
	}

	// Extract results
	var allthoughts []bson.M
	if err = result.All(ctx_new, &allthoughts); err != nil {
		log.Fatal(err)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allthoughts[0])
}

func GetTimeline(w http.ResponseWriter, r *http.Request) {
	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Set up context and cancellation function
	var ctx_new, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
	if err != nil || recordPerPage < 1 {
		recordPerPage = 10
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	startIndex := (page - 1) * recordPerPage
	// Overwrite startIndex if provided as query parameter
	if queryStartIndex := r.URL.Query().Get("startIndex"); queryStartIndex != "" {
		startIndex, err = strconv.Atoi(queryStartIndex)
		if err != nil || startIndex < 0 {
			startIndex = 0
		}
	}

	// get followDetailsModel for Loggedin user to fetch a list of following
	var LoggedinUserFollowDetails models.FollowDetails
	err = followCollection.FindOne(context.Background(), bson.M{"user_id": userId}).Decode(&LoggedinUserFollowDetails)
	if err != nil {
		http.Error(w, "error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	followinglist := LoggedinUserFollowDetails.Following

	// Convert userIDs slice to interface{} slice for $in operator
	var userIDInterfaces []interface{}
	userIDInterfaces = append(userIDInterfaces, userId) //append loggedin user's user id
	for _, miniuser := range followinglist {
		userIDInterfaces = append(userIDInterfaces, miniuser.User_id)
	}

	matchStage := bson.D{{Key: "$match", Value: bson.D{{Key: "user_id", Value: bson.D{{Key: "$in", Value: userIDInterfaces}}}}}} //get thoughts that match with all user ids in userIDinterfaces
	sortStage := bson.D{{Key: "$sort", Value: bson.D{{Key: "created_at", Value: -1}}}}                                           // Sort by created_at descending
	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}}}}}

	// Perform aggregation query
	result, err := thoughtCollection.Aggregate(ctx_new, mongo.Pipeline{
		matchStage, sortStage, groupStage, projectStage})
	if err != nil {
		http.Error(w, "error: error occured while listing thought items", http.StatusInternalServerError)
		return
	}

	// Extract results
	var allthoughts []bson.M
	if err = result.All(ctx_new, &allthoughts); err != nil {
		log.Fatal(err)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allthoughts[0])
}

func GetSearchUserResults(w http.ResponseWriter, r *http.Request) {
	var partialUserNameSearchKey string

	path := strings.TrimPrefix(r.URL.Path, "/user/search/")
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 0 && pathSegments[0] != "" {
		partialUserNameSearchKey = pathSegments[0]
		fmt.Printf("partialUserNameSearchKey, users having this as substr in username: %s\n", partialUserNameSearchKey)
	} else {
		http.Error(w, "partialUserNameSearchKey, users having this as substr in username is not found in the URL/Route", http.StatusBadRequest)
		return
	}

	// Access user information from request context
	ctx := r.Context()
	email := ctx.Value(contextKeys.ContextKey("email")).(string)
	firstName := ctx.Value(contextKeys.ContextKey("first_name")).(string)
	lastName := ctx.Value(contextKeys.ContextKey("last_name")).(string)
	userId := ctx.Value(contextKeys.ContextKey("user_id")).(string)
	userType := ctx.Value(contextKeys.ContextKey("user_type")).(string)

	// Use user information to log
	fmt.Printf("Authenticated User: %s (%s %s), User Id: %s, User Type: %s\n", email, firstName, lastName, userId, userType)

	// Set up context and cancellation function
	var ctx_new, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	// Parse query parameters for pagination
	recordPerPage, err := strconv.Atoi(r.URL.Query().Get("recordPerPage"))
	if err != nil || recordPerPage < 1 {
		recordPerPage = 10
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	startIndex := (page - 1) * recordPerPage
	// Overwrite startIndex if provided as query parameter
	if queryStartIndex := r.URL.Query().Get("startIndex"); queryStartIndex != "" {
		startIndex, err = strconv.Atoi(queryStartIndex)
		if err != nil || startIndex < 0 {
			startIndex = 0
		}
	}

	// Regex pattern for case-insensitive substring match
	pattern := fmt.Sprintf("^.*%s.*$", partialUserNameSearchKey)
	regex := primitive.Regex{Pattern: pattern, Options: "i"}

	matchStage := bson.D{{Key: "$match", Value: bson.D{
		{Key: "user_name", Value: regex}, // Match user_name with regex pattern
	}}}
	groupStage := bson.D{{Key: "$group", Value: bson.D{
		{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
		{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}}}}}
	projectStage := bson.D{
		{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "total_count", Value: 1},
			{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			{Key: "user_id", Value: 1},   // Include user_id field in the projection
			{Key: "user_name", Value: 1}, // Include user_name field in the projection
		}}}

	// Perform aggregation query
	result, err := userCollection.Aggregate(ctx_new, mongo.Pipeline{
		matchStage, groupStage, projectStage})
	if err != nil {
		http.Error(w, "error: error occured while listing user items", http.StatusInternalServerError)
		return
	}

	// Extract results
	var allusers []bson.M
	if err = result.All(ctx_new, &allusers); err != nil {
		log.Fatal(err)
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allusers[0])
}
