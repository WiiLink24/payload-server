package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"payload-server/common"
	"payload-server/logging"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/logrusorgru/aurora/v3"
)

var (
	stage1 []byte

	privateKeyProd *rsa.PrivateKey
	privateKeyDev  *rsa.PrivateKey

	payloadVersion []string

	deployment map[string][]string

	deployMutex sync.RWMutex
	serverName  string = "WiiLink"
)

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func replyHTTPError(w http.ResponseWriter, errorCode int, errorString string) {
	response := "<html>\n" +
		"<head><title>" + errorString + "</title></head>\n" +
		"<body>\n" +
		"<center><h1>" + errorString + "</h1></center>\n" +
		"<hr><center>" + serverName + "</center>\n" +
		"</body>\n" +
		"</html>\n"

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Connection", "close")
	w.WriteHeader(errorCode)
	w.Write([]byte(response))
}

func replyBadRequest(w http.ResponseWriter) {
	replyHTTPError(w, http.StatusBadRequest, "400 Bad Request")
}

func getPayload(moduleName string, channel []string, version int, game string) ([]byte, bool) {
	deployMutex.RLock()
	defer deployMutex.RUnlock()

	// Find most matching version
	var selected string
	var selectedInt int
	major := fmt.Sprintf("%d.", version)
	for _, v := range channel {
		if strings.HasPrefix(v, major) {
			selected = v
			break
		}

		vInt, err := strconv.Atoi(strings.Split(v, ".")[0])
		if err != nil {
			logging.Error(moduleName, "Failed to parse version:", v)
			return nil, false
		}

		if selected == "" {
			selected = v
			selectedInt = vInt
			continue
		}

		if vInt > version && vInt < selectedInt {
			selected = v
			selectedInt = vInt
			continue
		}

		if vInt < version && vInt > selectedInt {
			selected = v
			selectedInt = vInt
			continue
		}
	}

	dat, err := os.ReadFile("payload/" + selected + "/payload." + game + ".bin")
	if err != nil {
		logging.Error(moduleName, "Failed to read payload file")
	}
	return dat, err == nil
}

func handlePayloadRequest(moduleName string, w http.ResponseWriter, r *http.Request) {
	// Example request:
	// GET /payload?c=0&v=ff&d=00000000&f=00000000000000&k=0&g=RMCPD00&s=4e44b095817f8cfb62e6cffd57e9cfd411004a492784039ea4b2b7ca64717c91&h=9fdb6f60

	u, err := url.Parse(r.URL.String())
	if err != nil {
		logging.Error(moduleName, "Failed to parse URL")
		replyBadRequest(w)
		return
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		logging.Error(moduleName, "Failed to parse URL query")
		replyBadRequest(w)
		return
	}

	// Read payload ID (g) from URL
	game := query.Get("g")
	if len(game) != 7 && len(game) != 9 {
		logging.Error(moduleName, "Invalid or missing game ID:", aurora.Cyan(game))
		replyBadRequest(w)
		return
	}

	if (len(game) == 7 && game[4] != 'D') || (len(game) == 9 && game[4] != 'N') {
		logging.Error(moduleName, "Invalid game ID:", aurora.Cyan(game))
		replyBadRequest(w)
		return
	}

	for i := 0; i < 4; i++ {
		if (game[i] >= 'A' && game[i] <= 'Z') || (game[i] >= '0' && game[i] <= '9') {
			continue
		}

		logging.Error(moduleName, "Invalid game ID char:", aurora.Cyan(game))
		replyBadRequest(w)
		return
	}

	for i := 5; i < len(game); i++ {
		if isHexChar(game[i]) {
			continue
		}

		logging.Error(moduleName, "Invalid game ID version:", aurora.Cyan(game))
		replyBadRequest(w)
		return
	}

	channel, cOk := query["c"]
	if !cOk {
		channel = []string{"prod"} // Default to prod if not provided
	} else if len(channel) != 1 || channel[0] == "" {
		logging.Error(moduleName, "Invalid channel parameter")
		replyBadRequest(w)
		return
	}

	version := 0xff
	versionStr, vOk := query["v"]
	if vOk {
		if len(versionStr) != 1 || len(versionStr[0]) != 2 {
			logging.Error(moduleName, "Invalid version length:", aurora.BrightCyan(len(versionStr[0])))
			replyBadRequest(w)
			return
		}

		version64, err := strconv.ParseUint(versionStr[0], 16, 8)
		if err != nil {
			logging.Error(moduleName, "Invalid version hex string")
			replyBadRequest(w)
			return
		}

		version = int(version64)
	}

	keyId, kOk := query["k"]
	if !kOk {
		keyId = []string{"0"} // Default to channel 0 if not provided
	} else if len(keyId) != 1 || (keyId[0] != "0" && keyId[0] != "1") {
		logging.Error(moduleName, "Invalid key ID parameter")
		replyBadRequest(w)
		return
	}

	if !cOk || !vOk {
		// Attempt to receive missing information from console configuration
		deviceId := uint32(0)

		if deviceIdStr, ok := query["d"]; ok && (len(deviceIdStr) != 1 || (deviceIdStr[0] != "" && deviceIdStr[0] != "0")) {
			if len(deviceIdStr) != 1 || len(deviceIdStr[0]) != 8 {
				logging.Error(moduleName, "Invalid device ID length:", aurora.Cyan(len(deviceIdStr[0])))
				replyBadRequest(w)
				return
			}

			deviceId64, err := strconv.ParseUint(deviceIdStr[0], 16, 32)
			if err != nil {
				logging.Error(moduleName, "Invalid device ID hex string")
				replyBadRequest(w)
				return
			}

			deviceId = uint32(deviceId64)
		} else if cfcStr, ok := query["f"]; ok && (len(cfcStr) != 1 || (cfcStr[0] != "" && cfcStr[0] != "0")) {
			if len(cfcStr) != 1 || len(cfcStr[0]) != 14 {
				logging.Error(moduleName, "Invalid console friend code length:", aurora.Cyan(len(cfcStr[0])))
				replyBadRequest(w)
				return
			}

			cfc, err := strconv.ParseUint(cfcStr[0], 16, 64)
			if err != nil {
				logging.Error(moduleName, "Invalid console friend code hex string")
				replyBadRequest(w)
				return
			}

			// Fetch device ID as hollywood ID in the provided Wii Number
			common.DecodeWiiNumber(cfc, &deviceId, nil, nil, nil, nil)
		}

		if deviceId != 0 {
			// TODO: Fetch user config from the database
		}
	}

	deployChannel := deployment[channel[0]]
	if deployChannel == nil {
		logging.Error(moduleName, "Unknown channel:", aurora.Cyan(channel[0]))
		replyHTTPError(w, http.StatusNotFound, "404 Not Found")
		return
	}

	// Find most matching version
	dat, ok := getPayload(moduleName, deployChannel, version, game)
	if !ok {
		replyHTTPError(w, http.StatusNotFound, "404 Not Found")
		return
	}

	salt, ok := query["s"]
	if ok {
		if len(salt[0]) != 64 {
			logging.Error(moduleName, "Invalid salt length:", aurora.BrightCyan(len(salt[0])))
			replyBadRequest(w)
			return
		}

		_, err := hex.DecodeString(salt[0])
		if err != nil {
			logging.Error(moduleName, "Invalid salt hex string")
			replyBadRequest(w)
			return
		}

		saltHashTest, ok := query["h"]
		if !ok {
			logging.Error(moduleName, "Request is missing salt hash")
			replyBadRequest(w)
			return
		}

		if len(saltHashTest[0]) != 8 {
			logging.Error(moduleName, "Invalid salt hash length:", aurora.BrightCyan(len(saltHashTest[0])))
			replyBadRequest(w)
			return
		}

		saltHashTestData, err := hex.DecodeString(saltHashTest[0])
		if err != nil {
			logging.Error(moduleName, "Invalid salt hash hex string")
			replyBadRequest(w)
			return
		}

		// Generate the salt hash
		saltHashData := "payload"
		q := "?"
		if cOk {
			saltHashData += q + "c=" + channel[0]
			q = "&"
		}
		if vOk {
			saltHashData += q + "v=" + versionStr[0]
			q = "&"
		}
		if kOk {
			saltHashData += q + "k=" + keyId[0]
			q = "&"
		}
		if deviceIdStr, ok := query["d"]; ok && len(deviceIdStr) == 1 {
			saltHashData += q + "d=" + deviceIdStr[0]
			q = "&"
		}
		if cfcStr, ok := query["f"]; ok && len(cfcStr) == 1 {
			saltHashData += q + "f=" + cfcStr[0]
			q = "&"
		}
		saltHashData += q + "g=" + query.Get("g") + "&s=" + query.Get("s")

		hashCtx := sha256.New()
		_, err = hashCtx.Write([]byte(saltHashData))
		if err != nil {
			logging.Error(moduleName, "Failed to write salt hash data:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}

		saltHash := hashCtx.Sum(nil)
		// Check if the first 4 bytes of the salt hash match the provided test
		if !bytes.Equal(saltHashTestData, saltHash[:4]) {
			logging.Error(moduleName, "Salt hash mismatch")
			replyBadRequest(w)
			return
		}

		dat = append(append(dat[:0x110], saltHash...), dat[0x130:]...)

		// Hash our data then sign
		hash := sha256.New()
		_, err = hash.Write(dat[0x110:])
		if err != nil {
			logging.Error(moduleName, "Failed to write data hash:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}

		contentsHashSum := hash.Sum(nil)

		var rsaKey *rsa.PrivateKey
		if keyId[0] == "0" {
			rsaKey = privateKeyProd
		} else if keyId[0] == "1" {
			rsaKey = privateKeyDev
		}

		reader := rand.Reader
		signature, err := rsa.SignPKCS1v15(reader, rsaKey, crypto.SHA256, contentsHashSum)
		if err != nil {
			logging.Error(moduleName, "Failed to sign payload data:", err)
			replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
			return
		}

		dat = append(append(dat[:0x10], signature...), dat[0x110:]...)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(dat)))
	w.Write(dat)
}

func handleDeploymentRequest(moduleName string, w http.ResponseWriter, r *http.Request) {
	deployMutex.RLock()
	deploymentCopy := make(map[string][]string, len(deployment))
	for channel, versions := range deployment {
		deploymentCopy[channel] = make([]string, len(versions))
		copy(deploymentCopy[channel], versions)
	}
	deployMutex.RUnlock()

	// Convert deployment map to JSON
	data, err := json.Marshal(deploymentCopy)
	if err != nil {
		logging.Error(moduleName, "Failed to marshal deployment data:", err)
		replyHTTPError(w, http.StatusInternalServerError, "500 Internal Server Error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func loadPrivateKey(path string, rsaKey **rsa.PrivateKey) {
	// Load the private key from the specified path
	rsaData, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	rsaBlock, _ := pem.Decode(rsaData)
	parsedKey, err := x509.ParsePKCS8PrivateKey(rsaBlock.Bytes)
	if err != nil {
		panic(err)
	}

	var ok bool
	*rsaKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		panic("Unexpected key type")
	}
}

func loadDeploymentConfig() bool {
	moduleName := "DEPLOY"

	data, err := os.ReadFile("payload/deployment.json")
	if err != nil {
		logging.Error(moduleName, "Failed to read deployment config:", err)
		return false
	}

	newDeployment := make(map[string][]string)

	err = json.Unmarshal(data, &newDeployment)
	if err != nil {
		logging.Error(moduleName, "Failed to parse deployment config:", err)
		return false
	}

	var prod, beta bool

	// Verify that the deployment is correctly formatted
	for channel, versions := range newDeployment {
		if len(versions) == 0 {
			logging.Error(moduleName, "Channel", aurora.Cyan(channel), "has no versions defined")
			return false
		}
		if channel == "prod" {
			prod = true
		} else if channel == "beta" {
			beta = true
		}

		for _, version := range versions {
			// Check if the version is a valid semantic version
			parts := strings.Split(version, ".")
			if len(parts) < 2 || len(parts) > 3 {
				logging.Error(moduleName, "Invalid version format for channel", aurora.Cyan(channel), "version", aurora.Cyan(version))
				return false
			}
			var major, minor int
			if major, err = strconv.Atoi(parts[0]); err != nil || major > 255 || major < 0 {
				logging.Error(moduleName, "Invalid major version part for channel", aurora.Cyan(channel), "version", aurora.Cyan(version), "part", aurora.Cyan(parts[0]))
				return false
			}
			if minor, err = strconv.Atoi(parts[1]); err != nil || minor > 4096 || minor < 0 {
				logging.Error(moduleName, "Invalid minor version part for channel", aurora.Cyan(channel), "version", aurora.Cyan(version), "part", aurora.Cyan(parts[1]))
				return false
			}
			if len(parts) == 3 {
				var patch int
				if patch, err = strconv.Atoi(parts[2]); err != nil || patch > 4096 || patch < 0 {
					logging.Error(moduleName, "Invalid patch version part for channel", aurora.Cyan(channel), "version", aurora.Cyan(version), "part", aurora.Cyan(parts[2]))
					return false
				}
			}
			// Check if the payload directory exists
			if _, err := os.Stat("payload/" + version); os.IsNotExist(err) {
				logging.Error(moduleName, "Payload directory does not exist for channel", aurora.Cyan(channel), "version", aurora.Cyan(version))
				return false
			}
		}
	}

	if !prod || !beta {
		logging.Error(moduleName, "Missing required channels: prod and beta must be defined")
		return false
	}

	deployMutex.Lock()
	deployment = newDeployment
	deployMutex.Unlock()
	logging.Notice(moduleName, "Deployment config loaded successfully")
	return true
}

func main() {
	config := common.GetConfig()
	logging.SetLevel(*config.LogLevel)
	serverName = config.ServerName

	// Load payload private key
	loadPrivateKey("keys/prod.pem", &privateKeyProd)
	loadPrivateKey("keys/dev.pem", &privateKeyDev)

	// Start watcher for changes to the deployment config
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					logging.Info("PAYLOAD", "Deployment config changed, reloading")
					if !loadDeploymentConfig() {
						logging.Error("PAYLOAD", "Failed to reload deployment config")
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logging.Error("PAYLOAD", "File watcher error:", err)
			}
		}
	}()

	if err := watcher.Add("payload/deployment.json"); err != nil {
		panic(err)
	}

	if !loadDeploymentConfig() {
		logging.Error("PAYLOAD", "Failed to load deployment config, exiting")
		return
	}

	http.HandleFunc("GET /payload", func(w http.ResponseWriter, r *http.Request) {
		handlePayloadRequest("PAYLOAD/"+r.RemoteAddr, w, r)
	})

	http.HandleFunc("GET /payload/deployment", func(w http.ResponseWriter, r *http.Request) {
		handleDeploymentRequest("PAYLOAD/"+r.RemoteAddr, w, r)
	})

	logging.Info("PAYLOAD", "Starting server on", aurora.BrightCyan(config.PayloadServerAddress))
	if err := http.ListenAndServe(config.PayloadServerAddress, nil); err != nil {
		logging.Error("PAYLOAD", "Failed to start server:", err)
	}
}
