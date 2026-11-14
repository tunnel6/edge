package channel

import (
	"context"
	"fmt"
	"strings"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	logger "icool.io/yat/edge/pkg/log"
)

func (r *Registry) createOrUpdateHTTPLocked(req *CreateRequest, existingTarget *Channel, exists bool) (*CreateResult, error) {
	var existingRecord *ChannelRecord
	if r.store != nil {
		existingRecord, _ = r.store.Get(context.Background(), req.ID)
	}

	if req.Subdomain == "" {
		switch {
		case exists && existingTarget != nil && existingTarget.Subdomain != "":
			req.Subdomain = existingTarget.Subdomain
		case existingRecord != nil && existingRecord.Subdomain != "":
			req.Subdomain = strings.ToLower(strings.TrimSpace(existingRecord.Subdomain))
		}
	}

	if req.Subdomain == "" {
		req.Subdomain = r.ensureAutoSubdomainLocked(req, existingRecord)
	}

	// Only allow HTTP <-> HTTPS in-place update; other type switches close+recreate.
	if exists && existingTarget != nil &&
		existingTarget.Type != fbMsg.ChannelTypeHTTP &&
		existingTarget.Type != fbMsg.ChannelTypeHTTPS {
		if err := r.closeLocked(existingTarget); err != nil {
			return nil, err
		}
		exists = false
		existingTarget = nil
	}

	if exists && existingTarget != nil {
		return r.updateHTTPChannelLocked(req, existingTarget)
	}
	return r.createHTTPChannelLocked(req)
}

func (r *Registry) updateHTTPChannelLocked(req *CreateRequest, existingTarget *Channel) (*CreateResult, error) {
	previousBinding := existingTarget.CloneBinding()
	oldSessionID := existingTarget.SessionID
	oldDomain := existingTarget.Domain
	oldCustomDomain := existingTarget.AliasDomain

	expectedDomain, err := r.resources.ComposeDomain(req.Subdomain, "")
	if err != nil {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			ErrorMessage: fmt.Sprintf("compose domain failed: %v", err),
		}, nil
	}

	if req.AliasDomain != "" {
		if ownerID, ok := r.domainTargets[aliasRouteKey(req.AliasDomain)]; ok && ownerID != req.ID {
			return &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("allocate domain failed: alias domain already in use: %s", req.AliasDomain),
			}, nil
		}
	}

	if oldDomain != expectedDomain {
		if ownerID, ok := r.domainTargets[subdomainRouteKey(req.Subdomain)]; ok && ownerID != req.ID {
			return &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("allocate domain failed: subdomain already in use: %s", req.Subdomain),
			}, nil
		}

		if oldDomain != "" {
			r.resources.ReleaseDomain(oldDomain)
		}

		allocatedDomain, allocErr := r.resources.AllocateDomain(req.Subdomain, "")
		if allocErr != nil {
			return &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("allocate domain failed: %v", allocErr),
			}, nil
		}

		existingTarget.Domain = allocatedDomain
	}

	existingTarget.Type = req.Type
	existingTarget.SessionID = req.SessionID
	existingTarget.UserID = req.UserID
	existingTarget.DeviceID = req.DeviceID
	r.applyActorContext(existingTarget, req)
	existingTarget.LocalAddr = req.LocalAddr
	existingTarget.Subdomain = resolveAllocatedSubdomain(existingTarget.Domain, req.Subdomain)
	existingTarget.AliasDomain = req.AliasDomain
	existingTarget.ChannelKey = req.ChannelKey
	existingTarget.Protocol = req.Protocol
	existingTarget.LinkType = req.LinkType
	if len(req.PreferredLinks) > 0 {
		existingTarget.PreferredLinks = append([]string(nil), req.PreferredLinks...)
	} else {
		existingTarget.PreferredLinks = nil
	}
	existingTarget.AllowRelayFallback = req.AllowRelayFallback
	existingTarget.RequireDirect = req.RequireDirect
	if req.ConnRemoteAddr != "" {
		existingTarget.ConnRemoteAddr = req.ConnRemoteAddr
	}

	if oldSessionID != req.SessionID {
		r.removeFromSession(oldSessionID, req.ID)
	}
	r.attachToSessionLocked(req.SessionID, req.ID)
	r.syncHTTPRoutesLocked(existingTarget, oldDomain, oldCustomDomain)
	if err := r.upsertRuntimeLocked(existingTarget, previousBinding); err != nil {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			ErrorMessage: fmt.Sprintf("bind HTTP runtime failed: %v", err),
		}, nil
	}
	existingTarget.SetState(StateActive)

	result := &CreateResult{
		Success:     true,
		TargetID:    req.ID,
		Domain:      existingTarget.Domain,
		Subdomain:   existingTarget.Subdomain,
		AliasDomain: existingTarget.AliasDomain,
	}
	if err := r.saveHTTPRecordLocked(existingTarget); err != nil {
		logger.Warnf("failed to save channel to db: %v", err)
	}
	logger.Infof("target updated: id=%s, session=%s, domain=%s", req.ID, req.SessionID, existingTarget.Domain)
	return result, nil
}

func (r *Registry) createHTTPChannelLocked(req *CreateRequest) (*CreateResult, error) {
	target := NewChannel(req.ID, req.Type, req.SessionID, req.UserID, req.DeviceID, req.DeviceHostname, req.LocalAddr)
	r.applyActorContext(target, req)
	target.AliasDomain = req.AliasDomain
	target.ChannelKey = req.ChannelKey
	target.Protocol = req.Protocol
	target.LinkType = req.LinkType
	if len(req.PreferredLinks) > 0 {
		target.PreferredLinks = append([]string(nil), req.PreferredLinks...)
	}
	target.AllowRelayFallback = req.AllowRelayFallback
	target.RequireDirect = req.RequireDirect
	target.ConnRemoteAddr = req.ConnRemoteAddr

	if req.AliasDomain != "" {
		if ownerID, ok := r.domainTargets[aliasRouteKey(req.AliasDomain)]; ok && ownerID != req.ID {
			return &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("allocate domain failed: alias domain already in use: %s", req.AliasDomain),
			}, nil
		}
	}

	domain, err := r.resources.AllocateDomain(req.Subdomain, "")
	if err != nil {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			ErrorMessage: fmt.Sprintf("allocate domain failed: %v", err),
		}, nil
	}

	target.Domain = domain
	target.Subdomain = resolveAllocatedSubdomain(domain, req.Subdomain)
	r.targets[req.ID] = target
	r.attachToSessionLocked(req.SessionID, req.ID)
	r.syncHTTPRoutesLocked(target, "", "")
	if err := r.upsertRuntimeLocked(target, nil); err != nil {
		if key := subdomainRouteKey(target.Subdomain); key != "" {
			if ownerID, ok := r.domainTargets[key]; ok && ownerID == target.ID {
				delete(r.domainTargets, key)
			}
		}
		if key := aliasRouteKey(target.AliasDomain); key != "" {
			if ownerID, ok := r.domainTargets[key]; ok && ownerID == target.ID {
				delete(r.domainTargets, key)
			}
		}
		delete(r.targets, req.ID)
		r.removeFromSession(req.SessionID, req.ID)
		r.resources.ReleaseDomain(target.Domain)
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			ErrorMessage: fmt.Sprintf("bind HTTP runtime failed: %v", err),
		}, nil
	}
	target.SetState(StateActive)

	result := &CreateResult{
		Success:     true,
		TargetID:    req.ID,
		Domain:      domain,
		Subdomain:   target.Subdomain,
		AliasDomain: target.AliasDomain,
	}
	if err := r.saveHTTPRecordLocked(target); err != nil {
		logger.Warnf("failed to save channel to db: %v", err)
	}

	logger.Infof("target created: id=%s, type=%v, session=%s, domain=%s",
		req.ID, req.Type, req.SessionID, domain)
	return result, nil
}

func (r *Registry) ensureAutoSubdomainLocked(req *CreateRequest, existingRecord *ChannelRecord) string {
	if existingRecord != nil && existingRecord.Subdomain != "" {
		return strings.ToLower(strings.TrimSpace(existingRecord.Subdomain))
	}

	if r.store == nil {
		return EncodeID(time.Now().UnixNano())
	}

	tempRecord := &ChannelRecord{
		ChannelID:    req.ID,
		SessionID:    req.SessionID,
		Type:         req.Type,
		LocalAddr:    req.LocalAddr,
		Subdomain:    "",
		AliasDomain:  "",
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
	if err := r.store.Save(context.Background(), tempRecord); err != nil {
		logger.Warnf("failed to create temp record for auto-id: %v", err)
		return EncodeID(time.Now().UnixNano())
	}
	subdomain := EncodeID(time.Now().Unix() + tempRecord.ID)
	logger.Debugf("generated subdomain from db auto-id %d: %s", tempRecord.ID, subdomain)
	return subdomain
}

func (r *Registry) syncHTTPRoutesLocked(target *Channel, oldDomain, oldCustomDomain string) {
	oldSubdomainKey := subdomainRouteKey(extractSubdomain(oldDomain))
	oldAliasDomainKey := aliasRouteKey(oldCustomDomain)
	newSubdomainKey := subdomainRouteKey(target.Subdomain)
	newAliasDomainKey := aliasRouteKey(target.AliasDomain)

	shouldKeep := map[string]bool{}
	for _, key := range []string{newSubdomainKey, newAliasDomainKey} {
		if key != "" {
			shouldKeep[key] = true
		}
	}

	for _, key := range []string{oldSubdomainKey, oldAliasDomainKey} {
		if key == "" || shouldKeep[key] {
			continue
		}
		if ownerID, ok := r.domainTargets[key]; ok && ownerID == target.ID {
			delete(r.domainTargets, key)
		}
	}

	for _, key := range []string{newSubdomainKey, newAliasDomainKey} {
		if key == "" {
			continue
		}
		r.domainTargets[key] = target.ID
	}
}

func (r *Registry) saveHTTPRecordLocked(target *Channel) error {
	if r.store == nil {
		return nil
	}
	record := &ChannelRecord{
		ChannelID:    target.ID,
		SessionID:    target.SessionID,
		Type:         target.Type,
		LocalAddr:    target.LocalAddr,
		Port:         target.Port,
		Subdomain:    target.Subdomain,
		AliasDomain:  target.AliasDomain,
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
	return r.store.Save(context.Background(), record)
}

func (r *Registry) closeHTTPResourcesLocked(target *Channel) {
	if target.Domain != "" {
		r.resources.ReleaseDomain(target.Domain)
	}
	subdomain := strings.TrimSpace(target.Subdomain)
	if subdomain == "" {
		subdomain = extractSubdomain(target.Domain)
	}
	if key := subdomainRouteKey(subdomain); key != "" {
		if ownerID, ok := r.domainTargets[key]; ok && ownerID == target.ID {
			delete(r.domainTargets, key)
		}
	}
	if key := aliasRouteKey(target.AliasDomain); key != "" {
		if ownerID, ok := r.domainTargets[key]; ok && ownerID == target.ID {
			delete(r.domainTargets, key)
		}
	}
}

// SwitchAssignedDomain updates domains on existing HTTP channels after an assigned domain change.
func (r *Registry) SwitchAssignedDomain(assignedDomain string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	assignedDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(assignedDomain)), ".")

	updated := 0
	for _, target := range r.targets {
		if target.Type != fbMsg.ChannelTypeHTTP && target.Type != fbMsg.ChannelTypeHTTPS {
			continue
		}
		subdomain := strings.TrimSpace(target.Subdomain)
		if subdomain == "" {
			subdomain = extractSubdomain(target.Domain)
		}
		if subdomain == "" {
			continue
		}

		expectedDomain, err := r.resources.ComposeDomain(subdomain, "")
		if err != nil {
			logger.Warnf("compose domain failed for target %s: %v", target.ID, err)
			continue
		}
		if target.Domain == expectedDomain {
			continue
		}

		previousBinding := target.CloneBinding()
		oldDomain := target.Domain
		if oldDomain != "" {
			r.resources.ReleaseDomain(oldDomain)
		}
		newDomain, err := r.resources.AllocateDomain(subdomain, "")
		if err != nil {
			logger.Warnf("re-allocate domain failed for target %s: %v", target.ID, err)
			continue
		}

		target.Subdomain = subdomain
		target.Domain = newDomain
		r.syncHTTPRoutesLocked(target, oldDomain, target.AliasDomain)
		if err := r.upsertRuntimeLocked(target, previousBinding); err != nil {
			logger.Warnf("bind HTTP runtime failed for target %s: %v", target.ID, err)
			continue
		}
		if err := r.saveHTTPRecordLocked(target); err != nil {
			logger.Warnf("failed to persist switched domain for target %s: %v", target.ID, err)
		}
		updated++
	}

	return updated, nil
}
