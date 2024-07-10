package routes

import (
	"net/http"

	controller "github.com/ramyasreetejo/speak-mind/controllers"
	"github.com/ramyasreetejo/speak-mind/middleware"
)

func UserRoutes(incomingRoutes *http.ServeMux) {
	incomingRoutes.HandleFunc("/users", middleware.Authenticate(controller.GetUsers))                     //get
	incomingRoutes.HandleFunc("/users/", middleware.Authenticate(controller.GetUser))                     //get
	incomingRoutes.HandleFunc("/user/follow/", middleware.Authenticate(controller.Follow))                //path- user/follow/:user_id //post or put
	incomingRoutes.HandleFunc("/user/unfollow/", middleware.Authenticate(controller.UnFollow))            //path- user/unfollow/:user_id //post or put
	incomingRoutes.HandleFunc("/user/followers", middleware.Authenticate(controller.GetFollowers))        //get
	incomingRoutes.HandleFunc("/user/following", middleware.Authenticate(controller.GetFollowing))        //get
	incomingRoutes.HandleFunc("/user/newthought", middleware.Authenticate(controller.NewThought))         //post
	incomingRoutes.HandleFunc("/user/deletethought/", middleware.Authenticate(controller.DeleteThought))  //path- user/deletethought/:thought_id //delete
	incomingRoutes.HandleFunc("/user/thought/like/", middleware.Authenticate(controller.LikeThought))     //path- user/thought/like/:thought_id //post or put
	incomingRoutes.HandleFunc("/user/thought/unlike/", middleware.Authenticate(controller.UnlikeThought)) //path- user/thought/unlike/:thought_id //post or put
	incomingRoutes.HandleFunc("/user/mythoughts", middleware.Authenticate(controller.GetMyThoughts))      //get
	incomingRoutes.HandleFunc("/user/timeline", middleware.Authenticate(controller.GetTimeline))          //get
	incomingRoutes.HandleFunc("/user/search/", middleware.Authenticate(controller.GetSearchUserResults))  //path- user/search/:search_key //get
}
