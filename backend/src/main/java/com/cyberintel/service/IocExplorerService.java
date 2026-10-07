package com.cyberintel.service;

import com.cyberintel.dto.IocExplorerDtos;
import com.cyberintel.entity.IOC;
import com.cyberintel.entity.ThreatMatch;
import com.cyberintel.exception.ApiException;
import com.cyberintel.repository.IocRepository;
import com.cyberintel.repository.ThreatMatchRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/** Read-only view of stored, extracted APK IOCs and their stored intelligence correlations. */
@Service
@Transactional(readOnly = true)
public class IocExplorerService {
    private final IocRepository iocs;
    private final ThreatMatchRepository matches;

    public IocExplorerService(IocRepository iocs, ThreatMatchRepository matches) {
        this.iocs = iocs;
        this.matches = matches;
    }

    public List<IocExplorerDtos.Ioc> search(String email, String search, String type, String severity,
                                             String confidence, Long scanId) {
        List<IOC> rows = iocs.findExplorerIocsByUserEmail(email).stream()
                .filter(i -> scanId == null || Objects.equals(i.apkAnalysis.scan.getId(), scanId))
                .filter(i -> matchesFilter(i.type, type))
                .filter(i -> matchesFilter(i.severity, severity))
                .filter(i -> matchesFilter(i.confidence, confidence))
                .filter(i -> matchesSearch(i, search))
                .toList();
        return toDtos(rows);
    }

    public IocExplorerDtos.Ioc get(Long iocId, String email) {
        IOC ioc = iocs.findExplorerIocByIdAndUserEmail(iocId, email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "IOC not found."));
        return toDtos(List.of(ioc)).get(0);
    }

    private List<IocExplorerDtos.Ioc> toDtos(List<IOC> rows) {
        if (rows.isEmpty()) return List.of();
        List<Long> ids = rows.stream().map(i -> i.id).toList();
        Map<Long, List<ThreatMatch>> byIoc = matches.findExplorerMatchesByIocIdIn(ids).stream()
                .collect(Collectors.groupingBy(match -> match.ioc.id));
        return rows.stream().map(ioc -> toDto(ioc, byIoc.getOrDefault(ioc.id, List.of()))).toList();
    }

    private IocExplorerDtos.Ioc toDto(IOC ioc, List<ThreatMatch> threatMatches) {
        List<IocExplorerDtos.ThreatMatch> matchDtos = threatMatches.stream().map(match -> {
            var ti = match.threatIntelligence;
            return new IocExplorerDtos.ThreatMatch(match.id, match.status, match.matchType, match.severity,
                    match.confidence, match.description, match.matchedAt, ti != null ? ti.id : null,
                    ti != null ? ti.threatName : null, ti != null ? ti.threatFamily : null,
                    ti != null ? ti.category : null, ti != null ? ti.indicator : null,
                    ti != null ? ti.source : null);
        }).toList();
        return new IocExplorerDtos.Ioc(ioc.id, ioc.apkAnalysis.scan.getId(), ioc.apkAnalysis.scan.getTarget(),
                ioc.value, ioc.type, ioc.source, ioc.severity, ioc.confidence, ioc.description,
                ioc.firstSeen, ioc.lastSeen, ioc.createdAt, matchDtos);
    }

    private boolean matchesFilter(String value, String filter) {
        return filter == null || filter.isBlank() || (value != null && value.equalsIgnoreCase(filter.trim()));
    }

    private boolean matchesSearch(IOC ioc, String search) {
        if (search == null || search.isBlank()) return true;
        String term = search.trim().toLowerCase(Locale.ROOT);
        return contains(ioc.value, term) || contains(ioc.type, term) || contains(ioc.source, term)
                || contains(ioc.description, term) || contains(ioc.apkAnalysis.scan.getTarget(), term);
    }
    private boolean contains(String value, String term) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(term);
    }
}
