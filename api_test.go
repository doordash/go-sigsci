package sigsci

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type TestCreds struct {
	email string
	token string
	corp  string
	site  string
}

var testcreds = TestCreds{
	email: os.Getenv("SIGSCI_EMAIL"),
	token: os.Getenv("SIGSCI_TOKEN"),
	corp:  os.Getenv("SIGSCI_CORP"),
	site:  os.Getenv("SIGSCI_SITE"),
}

func ExampleClient_InviteUser() {
	email := testcreds.email
	password := testcreds.token
	sc, err := NewClient(email, password)
	if err != nil {
		log.Fatal(err)
	}

	invite := NewCorpUserInvite(RoleCorpUser, []SiteMembership{
		NewSiteMembership(testcreds.site, RoleSiteOwner),
	})

	_, err = sc.InviteUser(testcreds.corp, "test@test.net", invite)
	if err != nil {
		log.Fatal(err)
	}
}

func TestGoUserTokenClient(t *testing.T) {
	testCases := []struct {
		name  string
		email string
		token string
	}{
		{
			name:  "working user pass creds",
			email: testcreds.email,
			token: testcreds.token,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sc := NewTokenClient(testCase.email, testCase.token)
			if corps, err := sc.ListCorps(); err != nil {
				t.Fatal(err)
			} else {
				assert.Equal(t, testcreds.corp, corps[0].Name)
			}
		})
	}
}
func TestCreateUpdateDeleteSite(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp

	siteBody := CreateSiteBody{
		Name:                 "test-site",
		DisplayName:          "Test Site",
		AgentLevel:           "block",
		BlockHTTPCode:        407,
		BlockDurationSeconds: 86401,
		AgentAnonMode:        "",
	}
	siteresponse, err := sc.CreateSite(corp, siteBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "Test Site", siteresponse.DisplayName)
	assert.Equal(t, "block", siteresponse.AgentLevel)
	assert.Equal(t, 407, siteresponse.BlockHTTPCode)
	assert.Equal(t, 86401, siteresponse.BlockDurationSeconds)
	assert.Equal(t, "", siteresponse.AgentAnonMode)

	updateSite, err := sc.UpdateSite(corp, siteBody.Name, UpdateSiteBody{
		DisplayName:          "Test Site 2",
		AgentLevel:           "off",
		BlockDurationSeconds: 86402,
		BlockHTTPCode:        408,
		AgentAnonMode:        "EU",
	})

	assert.Equal(t, "Test Site 2", updateSite.DisplayName)
	assert.Equal(t, "off", updateSite.AgentLevel)
	assert.Equal(t, 408, updateSite.BlockHTTPCode)
	assert.Equal(t, 86402, updateSite.BlockDurationSeconds)
	assert.Equal(t, "EU", updateSite.AgentAnonMode)

	err = sc.DeleteSite(corp, siteBody.Name)
	if err != nil {
		t.Logf("%#v", err)
	}
}

func TestCreateReadUpdateDeleteSiteRules(t *testing.T) {

	createSiteRulesBody := CreateSiteRuleBody{
		Type:          "signal",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Signal:        "SQLI",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			Action{
				Type: "excludeSignal",
			},
		},
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createResp, err := sc.CreateSiteRule(corp, site, createSiteRulesBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRulesBody, createResp.CreateSiteRuleBody)

	readResp, err := sc.GetSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRulesBody, readResp.CreateSiteRuleBody)
	updateSiteRuleBody := CreateSiteRuleBody{
		Type:          "signal",
		GroupOperator: "all",
		Enabled:       true,
		Reason:        "Example site rule",
		Signal:        "SQLI",
		Expiration:    "",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "9.10.11.12",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
	}
	updateResp, err := sc.UpdateSiteRuleByID(corp, site, createResp.ID, updateSiteRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, updateSiteRuleBody, updateResp.CreateSiteRuleBody)

	readall, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateSiteRuleBody, readall.Data[0].CreateSiteRuleBody)

	err = sc.DeleteSiteRuleByID(corp, site, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnMarshalListData(t *testing.T) {
	resp := []byte(fmt.Sprintf(`{
		"totalCount": 1,
		"data": [
		  {
			"id": "5e84ec28bf612801c7f0f109",
			"siteNames": [
			  "%s"
			],
			"type": "signal",
			"enabled": true,
			"groupOperator": "all",
			"conditions": [
			  {
				"type": "single",
				"field": "ip",
				"operator": "equals",
				"value": "1.2.3.4"
			  }
			],
			"actions": [
			  {
				"type": "excludeSignal"
			  }
			],
			"signal": "SQLI",
			"reason": "Example site rule",
			"expiration": "",
			"createdBy": "test@gmail.com",
			"created": "2020-04-01T19:31:52Z",
			"updated": "2020-04-01T19:31:52Z"
		  }
		]
	  }`, testcreds.site))

	var responseRulesList ResponseSiteRuleBodyList
	err := json.Unmarshal(resp, &responseRulesList)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, responseRulesList.TotalCount)
	assert.Equal(t, 1, len(responseRulesList.Data))
	assert.Equal(t, "5e84ec28bf612801c7f0f109", responseRulesList.Data[0].ID)
}

func TestDeleteAllSiteRules(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	respList, err := sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range respList.Data {
		sc.DeleteSiteRuleByID(corp, site, rule.ID)
	}
	respList, err = sc.GetAllSiteRules(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 0, len(respList.Data))
}

func TestCreateReadUpdateDeleteSiteList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createSiteListBody := CreateListBody{
		Name:        "My new list",
		Type:        "ip",
		Description: "Some IPs we are putting in a list",
		Entries: []string{
			"4.5.6.7",
			"2.3.4.5",
			"1.2.3.4",
		},
	}
	createresp, err := sc.CreateSiteList(corp, site, createSiteListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteListBody, createresp.CreateListBody)

	readresp, err := sc.GetSiteListByID(corp, site, createresp.ID)
	assert.Equal(t, createSiteListBody, readresp.CreateListBody)

	updateSiteListBody := UpdateListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updateresp, err := sc.UpdateSiteListByID(corp, site, readresp.ID, updateSiteListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createSiteListBody, updateresp.CreateListBody)
	updatedSiteListBody := CreateListBody{
		Name:        "My new list",
		Type:        "ip",
		Description: "Some IPs we are updating in the list",
		Entries: []string{
			"2.3.4.5",
			"1.2.3.4",
			"3.4.5.6",
		},
	}
	assert.Equal(t, updatedSiteListBody, updateresp.CreateListBody)
	readall, err := sc.GetAllSiteLists(corp, site)
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedSiteListBody, readall.Data[0].CreateListBody)
	err = sc.DeleteSiteListByID(corp, site, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateMultipleRedactions(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody, createresp.CreateSiteRedactionBody)

	createSiteRedactionBody2 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 2,
	}
	createresp2, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody2)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody2, createresp2.CreateSiteRedactionBody)

	createSiteRedactionBody3 := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	createresp3, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody3)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSiteRedactionBody3, createresp3.CreateSiteRedactionBody)

	err = sc.DeleteSiteRedactionByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.DeleteSiteRedactionByID(corp, site, createresp2.ID)
	if err != nil {
		t.Fatal(err)
	}
	err = sc.DeleteSiteRedactionByID(corp, site, createresp3.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateListUpdateDeleteRedaction(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "privatefield",
		RedactionType: 2,
	}
	createresp, err := sc.CreateSiteRedaction(corp, site, createSiteRedactionBody)

	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, createSiteRedactionBody, createresp.CreateSiteRedactionBody)

	readresp, err := sc.GetSiteRedactionByID(corp, site, createresp.ID)
	assert.Equal(t, createSiteRedactionBody, readresp.CreateSiteRedactionBody)

	updateSiteRedactionBody := CreateSiteRedactionBody{
		Field:         "cookie",
		RedactionType: 0,
	}
	updatedresp, err := sc.UpdateSiteRedactionByID(corp, site, createresp.ID, updateSiteRedactionBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createSiteRedactionBody, updatedresp.CreateSiteRedactionBody)
	assert.Equal(t, updateSiteRedactionBody, updatedresp.CreateSiteRedactionBody)
	readall, err := sc.GetAllSiteRedactions(corp, site)
	assert.Equal(t, 1, len(readall.Data))
	// assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateSiteRedactionBody, readall.Data[0].CreateSiteRedactionBody)
	err = sc.DeleteSiteRedactionByID(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSiteCreateReadUpdateDeleteAlerts(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site

	createCustomAlert := CustomAlert{
		TagName:              "SQLI",
		LongName:             "Example Alert",
		BlockDurationSeconds: 1,
		Interval:             1,
		Threshold:            10,
		Enabled:              true,
		Action:               "flagged",
		Type:                 "siteAlert",
		FieldName:            "remoteIP",
	}
	createresp, err := sc.CreateSiteCustomAlert(corp, site, createCustomAlert)
	if err != nil {
		t.Fatal(err)
	}
	// set unknown fields just for equality
	createCustomAlert.ID = createresp.ID
	createCustomAlert.Created = createresp.Created
	createCustomAlert.CreatedBy = createresp.CreatedBy
	assert.Equal(t, createCustomAlert, createresp)
	readresp, err := sc.GetCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createCustomAlert, readresp)

	updateCustomAlert := CustomAlert{
		TagName:              "SQLI",
		LongName:             "Example Alert Updated",
		BlockDurationSeconds: 1,
		Interval:             10,
		Threshold:            10,
		Enabled:              true,
		Action:               "flagged",
		FieldName:            "remoteIP",
		Type:                 "siteAlert",
	}
	updateResp, err := sc.UpdateCustomAlert(corp, site, readresp.ID, updateCustomAlert)

	// set unknown fields just for equality
	updateCustomAlert.ID = updateResp.ID
	updateCustomAlert.Created = updateResp.Created
	updateCustomAlert.CreatedBy = updateResp.CreatedBy

	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createCustomAlert, updateResp)
	assert.Equal(t, updateCustomAlert, updateResp)
	allalerts, err := sc.ListCustomAlerts(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(allalerts))
	assert.Equal(t, updateCustomAlert, allalerts[0])
	err = sc.DeleteCustomAlert(corp, site, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}
func TestCreateReadUpdateDeleteCorpRule(t *testing.T) {
	createCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{testcreds.site},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "1.2.3.4",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "5.6.7.8",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
		Enabled:    true,
		Reason:     "test",
		Signal:     "SQLI",
		Expiration: "",
		CorpScope:  "specificSites",
	}
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	createResp, err := sc.CreateCorpRule(corp, createCorpRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%#v", createResp.CreateCorpRuleBody)
	assert.Equal(t, createCorpRuleBody, createResp.CreateCorpRuleBody)

	readResp, err := sc.GetCorpRuleByID(corp, createResp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, readResp, createResp)
	updateCorpRuleBody := CreateCorpRuleBody{
		SiteNames:     []string{testcreds.site},
		Type:          "signal",
		GroupOperator: "all",
		Conditions: []Condition{
			{
				Type:     "single",
				Field:    "ip",
				Operator: "equals",
				Value:    "5.6.7.8",
			},
			{
				Type:          "group",
				GroupOperator: "any",
				Conditions: []Condition{
					{
						Type:     "single",
						Field:    "ip",
						Operator: "equals",
						Value:    "6.7.8.9",
					},
				},
			},
		},
		Actions: []Action{
			{
				Type: "excludeSignal",
			},
		},
		Enabled:    true,
		Reason:     "test",
		Signal:     "SQLI",
		Expiration: "",
		CorpScope:  "specificSites",
	}
	updateResp, err := sc.UpdateCorpRuleByID(corp, createResp.ID, updateCorpRuleBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, updateCorpRuleBody, updateResp.CreateCorpRuleBody)
	readall, err := sc.GetAllCorpRules(corp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, 1, readall.TotalCount)
	assert.Equal(t, updateCorpRuleBody, readall.Data[0].CreateCorpRuleBody)
	err = sc.DeleteCorpRuleByID(corp, createResp.ID)

	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteCorpList(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	createCorpListBody := CreateListBody{
		Name:        "My new List",
		Type:        "ip",
		Description: "Some IPs we are putting in a list",
		Entries: []string{
			"4.5.6.7",
			"2.3.4.5",
			"1.2.3.4",
		},
	}
	createresp, err := sc.CreateCorpList(corp, createCorpListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createCorpListBody, createresp.CreateListBody)
	now := time.Now()
	expectedCreateResponse := ResponseListBody{
		CreateListBody: CreateListBody{
			Name:        "My new List",
			Type:        "ip",
			Description: "Some IPs we are putting in a list",
			Entries: []string{
				"4.5.6.7",
				"2.3.4.5",
				"1.2.3.4",
			},
		},
		ID:        "corp.my-new-list",
		CreatedBy: "",
		Created:   now,
		Updated:   now,
	}
	createresp.Created = now
	createresp.Updated = now
	createresp.CreatedBy = ""
	assert.Equal(t, expectedCreateResponse, createresp)

	readresp, err := sc.GetCorpListByID(corp, createresp.ID)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createCorpListBody, readresp.CreateListBody)

	updateCorpListBody := UpdateListBody{
		Description: "Some IPs we are updating in the list",
		Entries: Entries{
			Additions: []string{"3.4.5.6"},
			Deletions: []string{"4.5.6.7"},
		},
	}
	updateresp, err := sc.UpdateCorpListByID(corp, readresp.ID, updateCorpListBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, createCorpListBody, updateresp.CreateListBody)
	updatedCorpListBody := CreateListBody{
		Name:        "My new List",
		Type:        "ip",
		Description: "Some IPs we are updating in the list",
		Entries: []string{
			"2.3.4.5",
			"1.2.3.4",
			"3.4.5.6",
		},
	}
	assert.Equal(t, updatedCorpListBody, updateresp.CreateListBody)
	readall, err := sc.GetAllCorpLists(corp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedCorpListBody, readall.Data[0].CreateListBody)
	err = sc.DeleteCorpListByID(corp, readresp.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteCorpTag(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	createSignalTagBody := CreateSignalTagBody{
		ShortName:   "Example Signal Tag 1",
		Description: "An example of a custom signal tag",
	}
	createresp, err := sc.CreateCorpSignalTag(corp, createSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSignalTagBody, createresp.CreateSignalTagBody)
	expectedCreateResponse := ResponseSignalTagBody{
		CreateSignalTagBody: CreateSignalTagBody{
			ShortName:   "Example Signal Tag 1",
			Description: "An example of a custom signal tag",
		},
		TagName:       "corp.example-signal-tag-1",
		LongName:      "Example Signal Tag 1",
		Configurable:  false,
		Informational: false,
		NeedsResponse: false,
		CreatedBy:     "",
		Created:       time.Time{},
	}
	createresp.Created = time.Time{}
	createresp.CreatedBy = ""
	assert.Equal(t, expectedCreateResponse, createresp)
	readresp, err := sc.GetCorpSignalTagByID(corp, createresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSignalTagBody, readresp.CreateSignalTagBody)
	updateSignalTagBody := UpdateSignalTagBody{
		Description: "An example of a custom signal tag - UPDATE",
	}
	updateresp, err := sc.UpdateCorpSignalTagByID(corp, createresp.TagName, updateSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	updatedSignalTagBody := CreateSignalTagBody{
		ShortName:   "Example Signal Tag 1",
		Description: "An example of a custom signal tag - UPDATE",
	}
	assert.Equal(t, updatedSignalTagBody, updateresp.CreateSignalTagBody)
	readall, err := sc.GetAllCorpSignalTags(corp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedSignalTagBody, readall.Data[0].CreateSignalTagBody)
	err = sc.DeleteCorpSignalTagByID(corp, readresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateReadUpdateDeleteSignalTag(t *testing.T) {
	sc := NewTokenClient(testcreds.email, testcreds.token)
	corp := testcreds.corp
	site := testcreds.site
	createSignalTagBody := CreateSignalTagBody{
		ShortName:   "example-signal-tag",
		Description: "An example of a custom signal tag",
	}
	createresp, err := sc.CreateSiteSignalTag(corp, site, createSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	readresp, err := sc.GetSiteSignalTagByID(corp, site, createresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, createSignalTagBody, readresp.CreateSignalTagBody)
	updateSignalTagBody := UpdateSignalTagBody{
		Description: "An example of a custom signal tag - UPDATE",
	}
	updateresp, err := sc.UpdateSiteSignalTagByID(corp, site, createresp.TagName, updateSignalTagBody)
	if err != nil {
		t.Fatal(err)
	}
	updatedSignalTagBody := CreateSignalTagBody{
		ShortName:   "example-signal-tag",
		Description: "An example of a custom signal tag - UPDATE",
	}
	assert.Equal(t, updatedSignalTagBody, updateresp.CreateSignalTagBody)
	readall, err := sc.GetAllSiteSignalTags(corp, site)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(readall.Data))
	assert.Equal(t, updatedSignalTagBody, readall.Data[0].CreateSignalTagBody)
	err = sc.DeleteSiteSignalTagByID(corp, site, readresp.TagName)
	if err != nil {
		t.Fatal(err)
	}
}
