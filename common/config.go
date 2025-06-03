package common

import (
	"encoding/xml"
	"os"
)

type Config struct {
	Username        string `xml:"username"`
	Password        string `xml:"password"`
	DatabaseAddress string `xml:"databaseAddress"`
	DatabaseName    string `xml:"databaseName"`

	PayloadServerAddress string `xml:"payloadServerAddress"`

	LogLevel *int `xml:"logLevel"`

	APISecret string `xml:"apiSecret"`

	ServerName string `xml:"serverName,omitempty"`
}

var config Config
var configLoaded bool

func GetConfig() Config {
	if configLoaded {
		return config
	}

	data, err := os.ReadFile("config.xml")
	if err != nil {
		panic(err)
	}

	config.ServerName = "WiiLink"

	err = xml.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}

	if config.LogLevel == nil {
		level := 4
		config.LogLevel = &level
	}

	return config
}
