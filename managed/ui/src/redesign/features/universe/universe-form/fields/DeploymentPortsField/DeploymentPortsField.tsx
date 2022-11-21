import React, { FC } from 'react';
import { Box, Grid } from '@material-ui/core';
import { Controller, useWatch, useFormContext } from 'react-hook-form';
import { DEFAULT_COMMUNICATION_PORTS, UniverseFormData } from '../../utils/dto';
import { YBInput, YBToggleField, YBLabel } from '../../../../../components';
import { useTranslation } from 'react-i18next';
import {
  COMMUNICATION_PORTS_FIELD,
  YCQL_FIELD,
  YSQL_FIELD,
  YEDIS_FIELD,
  CUSTOMIZE_PORT_FIELD
} from '../../utils/constants';

interface DeploymentPortsFieldids {
  disabled: boolean;
}

const MAX_PORT = 65535;

export const DeploymentPortsField: FC<DeploymentPortsFieldids> = ({ disabled }) => {
  const { control } = useFormContext<UniverseFormData>();
  const { t } = useTranslation();

  const ysqlEnabled = useWatch({ name: YSQL_FIELD });
  const ycqlEnabled = useWatch({ name: YCQL_FIELD });
  const yedisEnabled = useWatch({ name: YEDIS_FIELD });

  const customizePort = useWatch({ name: CUSTOMIZE_PORT_FIELD });

  const portsConfig = [
    { id: 'masterHttpPort', visible: true },
    { id: 'masterRpcPort', visible: true },
    { id: 'tserverHttpPort', visible: true },
    { id: 'tserverRpcPort', visible: true },
    { id: 'redisServerHttpPort', visible: yedisEnabled },
    { id: 'redisServerRpcPort', visible: yedisEnabled },
    { id: 'yqlServerHttpPort', visible: ycqlEnabled },
    { id: 'yqlServerRpcPort', visible: ycqlEnabled },
    { id: 'ysqlServerHttpPort', visible: ysqlEnabled },
    { id: 'ysqlServerRpcPort', visible: ysqlEnabled }
  ].filter((ports) => ports.visible);

  return (
    <Controller
      name={COMMUNICATION_PORTS_FIELD}
      render={({ field: { value, onChange } }) => {
        return (
          <Box display="flex" alignItems="flex-start">
            <YBLabel>{t('universeForm.advancedConfig.overridePorts')}</YBLabel>
            <Box flex={1} display="flex" flexDirection="column">
              <YBToggleField
                name={CUSTOMIZE_PORT_FIELD}
                inputProps={{
                  'data-testid': 'customizePort'
                }}
                control={control}
                disabled={disabled}
              />
              {customizePort && (
                <Grid container>
                  {portsConfig.map((item) => (
                    <Grid lg={6}>
                      <Box display="flex" mr={4}>
                        <YBLabel>{t(`universeForm.advancedConfig.${item.id}`)}</YBLabel>
                        <Box flex={1}>
                          <YBInput
                            disabled={disabled}
                            className={
                              Number(value[item.id]) ===
                              Number(DEFAULT_COMMUNICATION_PORTS[item.id])
                                ? ''
                                : 'communication-ports-editor__overridden-value'
                            }
                            value={value[item.id]}
                            onChange={(event) =>
                              onChange({ ...value, [item.id]: event.target.value })
                            }
                            onBlur={(event) => {
                              let port =
                                Number(event.target.value.replace(/\D/g, '')) ||
                                DEFAULT_COMMUNICATION_PORTS[item.id];
                              port = port > MAX_PORT ? MAX_PORT : port;
                              onChange({ ...value, [item.id]: port });
                            }}
                          />
                        </Box>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          </Box>
        );
      }}
    />
  );
};

//hidden for k8s