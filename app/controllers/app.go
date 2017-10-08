package controllers

import (
	"encoding/json"
	"fmt"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	"github.com/HouzuoGuo/tiedot/db"
	"github.com/revel/revel"
)

var RatDB *db.DB

type User struct {
	*revel.Controller
}

func (c User) AddUser() revel.Result {
	name := c.Params.Form.Get("name")
	username := c.Params.Form.Get("username")
	password := c.Params.Form.Get("password")
	isAdmin := c.Params.Form.Get("isAdmin")
	// check if user already exists
	users := RatDB.Use("Users")
	var query interface{}
	json.Unmarshal([]byte(fmt.Sprintf(`[{"eq": "%s", "in": ["username"]}]`, username)), &query)
	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	if err := db.EvalQuery(query, users, &queryResult); err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}
	for range queryResult {
		res := make(map[string]interface{})
		res["status"] = 0
		return c.RenderJSON(res)
	}
	// insert user
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}
	_, err = users.Insert(map[string]interface{}{
		"name":     name,
		"username": username,
		"password": string(hashedPassword),
		"isAdmin":  isAdmin})
	if err != nil {
		revel.ERROR.Println(err)
		return c.RenderError(err)
	}

	res := make(map[string]interface{})
	res["status"] = 1
	return c.RenderJSON(res)
}

func (c User) CheckUser() revel.Result {
	username := c.Params.Form.Get("username")
	password := c.Params.Form.Get("password")
	if len(username) > 0 {
		// check if user credentials are valid
		users := RatDB.Use("Users")
		var query interface{}
		json.Unmarshal([]byte(fmt.Sprintf(`[{"eq": "%s", "in": ["username"]}]`, username)), &query)
		queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
		if err := db.EvalQuery(query, users, &queryResult); err != nil {
			return c.RenderError(err)
		}
		for id := range queryResult {
			readBack, err := users.Read(id)
			if err != nil {
				return c.RenderError(err)
			}
			err = bcrypt.CompareHashAndPassword([]byte(readBack["password"].(string)), []byte(password))
			if err == nil {
				res := make(map[string]interface{})
				res["status"] = 1
				return c.RenderJSON(res)
			}
		}
	}

	res := make(map[string]interface{})
	res["status"] = 0
	return c.RenderJSON(res)
}

func (c User) AllUsers() revel.Result {
	users := RatDB.Use("Users")
	var query interface{}
	json.Unmarshal([]byte(fmt.Sprintf(`["all"]`)), &query)
	queryResult := make(map[int]struct{}) // query result (document IDs) goes into map keys
	if err := db.EvalQuery(query, users, &queryResult); err != nil {
		return c.RenderError(err)
	}
	res := make(map[string]interface{})
	for id := range queryResult {
		readBack, err := users.Read(id)
		if err != nil {
			return c.RenderError(err)
		}
		if err == nil {
			res[strconv.Itoa(id)] = readBack
		}
	}
	return c.RenderJSON(res)
}
