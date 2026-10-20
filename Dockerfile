# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/DeskPilot/DeskPilot.csproj src/DeskPilot/
RUN dotnet restore src/DeskPilot/DeskPilot.csproj
COPY src/ src/
RUN dotnet publish src/DeskPilot/DeskPilot.csproj -c Release -o /app --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
RUN mkdir -p /data && chown -R $APP_UID /data
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=21114 \
    DeskPilot__DataPath=/data \
    DOTNET_gcServer=0
VOLUME /data
EXPOSE 21114
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["dotnet", "DeskPilot.dll", "--healthcheck"]
ENTRYPOINT ["dotnet", "DeskPilot.dll"]
