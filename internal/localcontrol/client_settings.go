package localcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/k2exe/aamm-ng/internal/appconfig"
)

func (client *Client) SettingsRead(
	ctx context.Context,
) (appconfig.Config, error) {
	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsRead,
		},
	)
	if err != nil {
		return appconfig.Config{}, err
	}

	return decodeSettingsResult(response)
}

func (client *Client) SettingsReplace(
	ctx context.Context,
	config appconfig.Config,
) (appconfig.Config, error) {
	if err := config.Validate(); err != nil {
		return appconfig.Config{}, err
	}

	audit, err := client.mutationAuditFromContext(ctx)
	if err != nil {
		return appconfig.Config{}, err
	}

	response, err := client.Call(
		ctx,
		Request{
			Version:   ProtocolVersion,
			Operation: OperationSettingsReplace,
			Settings:  &config,
			Audit:     &audit,
		},
	)
	if err != nil {
		return appconfig.Config{}, err
	}

	return decodeSettingsResult(response)
}

func decodeSettingsResult(
	response Response,
) (appconfig.Config, error) {
	if !response.OK {
		return decodeTypedResult[appconfig.Config](response)
	}

	if response.Result == nil {
		return appconfig.Config{}, fmt.Errorf(
			"%w: successful settings response missing result",
			ErrInvalidResponse,
		)
	}

	data, err := json.Marshal(response.Result)
	if err != nil {
		return appconfig.Config{}, fmt.Errorf(
			"%w: encode settings result",
			ErrInvalidResponse,
		)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var config appconfig.Config

	if err := decoder.Decode(&config); err != nil {
		return appconfig.Config{}, fmt.Errorf(
			"%w: invalid application settings result",
			ErrInvalidResponse,
		)
	}

	var extra any

	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return appconfig.Config{}, fmt.Errorf(
			"%w: invalid application settings result",
			ErrInvalidResponse,
		)
	}

	if err := config.Validate(); err != nil {
		return appconfig.Config{}, fmt.Errorf(
			"%w: invalid application settings result",
			ErrInvalidResponse,
		)
	}

	return config, nil
}
